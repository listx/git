#include "git-compat-util.h"
#include "config.h"
#include "environment.h"
#include "gettext.h"
#include "string-list.h"
#include "run-command.h"
#include "commit.h"
#include "trailer.h"
#include "list.h"
/*
 * Copyright (c) 2013, 2014 Christian Couder <chriscool@tuxfamily.org>
 */

struct trailer_block {
	/*
	 * True if there is a blank line before the location pointed to by
	 * "start".
	 */
	int blank_line_before_trailer;

	/*
	 * The locations of the start and end positions of the trailer block
	 * found, as offsets from the beginning of the source text from which
	 * this trailer block was parsed. If no trailer block is found, these
	 * are both set to 0.
	 */
	size_t start, end;

	/*
	 * Array of trailer strings found.
	 */
	char **trailer_strings;
	size_t trailer_nr;
};

struct trailer_conf {
	char *key_alias;
	char *key;
	char *command;
	char *cmd;
	enum trailer_where where;
	enum trailer_if_exists if_exists;
	enum trailer_if_missing if_missing;
};

static struct trailer_conf default_trailer_conf;

struct trailer {
	struct list_head list;
	/*
	 * If this is not a trailer line, the line is stored in value
	 * (excluding the terminating newline) and key is NULL.
	 */
	char *key;
	char *value;
};

struct trailer_template {
	struct list_head list;
	char *key;
	char *value;
	struct trailer_conf conf;
	struct trailer *target;
};

static LIST_HEAD(templates_from_conf);

static char *separators = ":";

const char *trailer_default_separators(void)
{
	return separators;
}

static int configured;

#define TRAILER_ARG_STRING "$ARG"

static const char *git_generated_prefixes[] = {
	"Signed-off-by: ",
	"(cherry picked from commit ",
	NULL
};

/* Iterate over the elements of the list. */
#define list_for_each_dir(pos, head, is_reverse) \
	for (pos = is_reverse ? (head)->prev : (head)->next; \
		pos != (head); \
		pos = is_reverse ? pos->prev : pos->next)

static int after_or_end(enum trailer_where where)
{
	return (where == WHERE_AFTER) || (where == WHERE_END);
}

/*
 * Return the length of the string not including any final
 * punctuation. E.g., the input "Signed-off-by:" would return
 * 13, stripping the trailing punctuation but retaining
 * internal punctuation.
 */
static size_t key_len_without_separator(const char *key, size_t len)
{
	while (len > 0 && !isalnum(key[len - 1]))
		len--;
	return len;
}

static int same_key(struct trailer *a, struct trailer_template *b)
{
	size_t a_len, b_len, min_len;

	if (!a->key)
		return 0;

	a_len = key_len_without_separator(a->key, strlen(a->key));
	b_len = key_len_without_separator(b->key, strlen(b->key));
	min_len = (a_len > b_len) ? b_len : a_len;

	return !strncasecmp(a->key, b->key, min_len);
}

static int same_value(struct trailer *a, struct trailer_template *b)
{
	return !strcasecmp(a->value, b->value);
}

static int same_trailer(struct trailer *a, struct trailer_template *b)
{
	return same_key(a, b) && same_value(a, b);
}

static inline int is_blank_line(const char *str)
{
	const char *s = str;
	while (*s && *s != '\n' && isspace(*s))
		s++;
	return !*s || *s == '\n';
}

static inline void strbuf_replace(struct strbuf *sb, const char *a, const char *b)
{
	const char *ptr = strstr(sb->buf, a);
	if (ptr)
		strbuf_splice(sb, ptr - sb->buf, strlen(a), b, strlen(b));
}

static void free_trailer(struct trailer *trailer)
{
	free(trailer->key);
	free(trailer->value);
	free(trailer);
}

static void free_template(struct trailer_template *template)
{
	free(template->conf.key_alias);
	free(template->conf.key);
	free(template->conf.command);
	free(template->conf.cmd);
	free(template->key);
	free(template->value);
	free(template);
}

static char last_non_space_char(const char *s)
{
	int i;
	for (i = strlen(s) - 1; i >= 0; i--)
		if (!isspace(s[i]))
			return s[i];
	return '\0';
}

/*
 * Check if the template's key and value has not been seen yet in either the
 * current trailer or the rest of trailers, in one direction. That is, we only
 * check all trailers before "current", or all trailers after "current". Using
 * "current" is an optimization to skip over trailers that we already know to
 * not have a duplicate.
 */
static int same_trailer_found(struct trailer_template *template,
			      struct trailer *current,
			      struct list_head *start)
{
	int search_backwards = after_or_end(template->conf.where);
	struct list_head *next;

	do {
		if (same_trailer(current, template))
			return 1;

		next = current->list.next;
		if (search_backwards)
			next = current->list.prev;

		current = list_entry(next, struct trailer, list);
	} while (next != start);

	return 0;
}

static char *run_command_from_template(struct trailer_conf *conf,
				       const char *arg)
{
	struct strbuf cmd = STRBUF_INIT;
	struct strbuf buf = STRBUF_INIT;
	struct child_process cp = CHILD_PROCESS_INIT;
	char *result;

	if (conf->cmd) {
		strbuf_addstr(&cmd, conf->cmd);
		strvec_push(&cp.args, cmd.buf);
		if (arg)
			strvec_push(&cp.args, arg);
	} else if (conf->command) {
		strbuf_addstr(&cmd, conf->command);
		if (arg)
			strbuf_replace(&cmd, TRAILER_ARG_STRING, arg);
		strvec_push(&cp.args, cmd.buf);
	}
	strvec_pushv(&cp.env, (const char **)local_repo_env);
	cp.no_stdin = 1;
	cp.use_shell = 1;

	if (capture_command(&cp, &buf, 1024)) {
		error(_("running trailer command '%s' failed"), cmd.buf);
		strbuf_release(&buf);
		result = xstrdup("");
	} else {
		strbuf_trim(&buf);
		result = strbuf_detach(&buf, NULL);
	}

	strbuf_release(&cmd);
	return result;
}

/*
 * Prepare the template so that it is pointing to a new, blank trailer target
 * (correctly positioned somewhere inside "trailers") which we would like to
 * apply on top of (overwrite).
 */
static void create_new_target_for(struct trailer_template *template,
				  struct trailer *middle,
				  struct list_head *trailers)
{
	struct trailer *target = xcalloc(1, sizeof(*target));

	switch (template->conf.where) {
	case WHERE_START:
		list_add(&target->list, trailers);
		break;
	case WHERE_BEFORE:
		list_add(&target->list,
			 middle ? middle->list.prev : trailers);
		break;
	case WHERE_AFTER:
		list_add_tail(&target->list,
			      middle ? middle->list.next : trailers);
		break;
	case WHERE_END:
		list_add_tail(&target->list, trailers);
		break;
	default:
		BUG("trailer.c: unhandled type %d", template->conf.where);
	}

	template->target = target;
}

/*
 * Prepare the template by running the command (if any) requested by the
 * template in order to populate the template's value field.
 */
static void populate_template_value(struct trailer_template *template)
{
	if (template->conf.command || template->conf.cmd) {
		/*
		 * Determine argument to pass into the command.
		 */
		const char *arg;
		if (template->value && template->value[0])
			arg = template->value;
		else
			arg = xstrdup("");

		template->value = run_command_from_template(&template->conf, arg);
		free((char *)arg);
	}
}

/*
 * Use the template by applying it at the target trailer.
 */
static void apply(struct trailer_template *template)
{
	free(template->target->key);
	free(template->target->value);
	template->target->key = xstrdup(template->key);
	template->target->value = xstrdup(template->value);
}

/*
 * Given an existing trailer that was found with the same key, consider applying
 * the template anyway over an existing (EXISTS_REPLACE) or new trailer
 * (EXISTS_ADD_*).
 */
static void maybe_add_if_exists(struct trailer_template *template,
				struct trailer *existing_trailer,
				struct list_head *trailers)
{
	struct trailer *neighbor;
	enum trailer_where where = template->conf.where;

	switch (template->conf.if_exists) {
	case EXISTS_DO_NOTHING:
		break;
	case EXISTS_REPLACE:
		populate_template_value(template);
		template->target = existing_trailer;
		apply(template);
		break;
	case EXISTS_ADD:
		populate_template_value(template);
		create_new_target_for(template, existing_trailer, trailers);
		apply(template);
		break;
	/*
	 * Add a new trailer if there isn't one already with the same key and
	 * value. In other words, avoid adding what would become a duplicate
	 * trailer if we have the same trailer already somewhere in "trailers"
	 *
	 * The existing_trailer only has the same key as the template, so we
	 * have to check each trailer in "trailers" (starting with
	 * existing_trailer itself).
	 */
	case EXISTS_ADD_IF_DIFFERENT:
		populate_template_value(template);
		if (!same_trailer_found(template, existing_trailer, trailers)) {
			create_new_target_for(template, existing_trailer,
					      trailers);
			apply(template);
		}
		break;
	/*
	 * This is like EXISTS_ADD_IF_DIFFERENT in that it wants to avoid
	 * creating a duplicate trailer. But instead of searching through all
	 * trailers, it only looks at one (existing) trailer that will be next
	 * to us if we do end up adding a new trailer. In other words, if the
	 * input does not have any duplicates, then creating duplicates is OK as
	 * long as we wouldn't end up with 2 _consecutive_ duplicates.
	 */
	case EXISTS_ADD_IF_DIFFERENT_NEIGHBOR:
		/*
		 * If we want to add this trailer at the start or end, then
		 * there is only one neighbor to check for being a duplicate
		 * because there won't be a trailer before or after us,
		 * respectively.
		 *
		 * If WHERE_BEFORE or WHERE_AFTER, we will be sandwiching
		 * ourselves between existing_trailer and another one (assuming
		 * existing_trailer itself is not at the start or end). But we
		 * still only need to check one trailer (existing_neighbor).
		 * That's because the other trailer (if any) was already checked
		 * for the same key (see find_same_and_apply_arg()) just before
		 * we were called. That is, we're only called when we found a
		 * matching trailer with the same key (hence the name
		 * "existing_trailer"), so the other trailer (if any) is
		 * guaranteed to have at least a different key than us already
		 * (making the checking of the value moot).
		 */
		if (where == WHERE_START)
			neighbor = list_entry(trailers->next, struct trailer,
					      list);
		else if (where == WHERE_END)
			neighbor = list_entry(trailers->prev, struct trailer,
					      list);
		else
			neighbor = existing_trailer;

		populate_template_value(template);
		if (!same_trailer(neighbor, template)) {
			create_new_target_for(template, existing_trailer,
					      trailers);
			apply(template);
		}
		break;
	default:
		BUG("trailer.c: unhandled value %d",
		    template->conf.if_exists);
	}
}

static void maybe_add_if_missing(struct trailer_template *template,
				 struct list_head *trailers)
{
	switch (template->conf.if_missing) {
	case MISSING_DO_NOTHING:
		break;
	case MISSING_ADD:
		populate_template_value(template);
		create_new_target_for(template, NULL, trailers);
		apply(template);
		break;
	default:
		BUG("trailer.c: unhandled value %d",
		    template->conf.if_missing);
	}
}

static int find_same_and_apply_arg(struct trailer_template *template,
				   struct list_head *trailers)
{
	struct list_head *pos;
	struct trailer *current;

	enum trailer_where where = template->conf.where;
	int backwards = after_or_end(where);

	if (list_empty(trailers))
		return 0;

	list_for_each_dir(pos, trailers, backwards) {
		current = list_entry(pos, struct trailer, list);
		if (!same_key(current, template))
			continue;
		maybe_add_if_exists(template, current, trailers);
		return 1;
	}
	return 0;
}

void apply_trailer_templates(struct list_head *templates,
			     struct list_head *trailers)
{
	struct list_head *pos, *p;
	struct trailer_template *template;

	list_for_each_safe(pos, p, templates) {
		int applied = 0;
		template = list_entry(pos, struct trailer_template, list);

		list_del(pos);

		applied = find_same_and_apply_arg(template, trailers);

		if (!applied)
			maybe_add_if_missing(template, trailers);

		free_template(template);
	}
}

int trailer_set_where(enum trailer_where *item, const char *value)
{
	if (!value)
		*item = WHERE_DEFAULT;
	else if (!strcasecmp("after", value))
		*item = WHERE_AFTER;
	else if (!strcasecmp("before", value))
		*item = WHERE_BEFORE;
	else if (!strcasecmp("end", value))
		*item = WHERE_END;
	else if (!strcasecmp("start", value))
		*item = WHERE_START;
	else
		return -1;
	return 0;
}

int trailer_set_if_exists(enum trailer_if_exists *item, const char *value)
{
	if (!value)
		*item = EXISTS_DEFAULT;
	else if (!strcasecmp("addIfDifferent", value))
		*item = EXISTS_ADD_IF_DIFFERENT;
	else if (!strcasecmp("addIfDifferentNeighbor", value))
		*item = EXISTS_ADD_IF_DIFFERENT_NEIGHBOR;
	else if (!strcasecmp("add", value))
		*item = EXISTS_ADD;
	else if (!strcasecmp("replace", value))
		*item = EXISTS_REPLACE;
	else if (!strcasecmp("doNothing", value))
		*item = EXISTS_DO_NOTHING;
	else
		return -1;
	return 0;
}

int trailer_set_if_missing(enum trailer_if_missing *item, const char *value)
{
	if (!value)
		*item = MISSING_DEFAULT;
	else if (!strcasecmp("doNothing", value))
		*item = MISSING_DO_NOTHING;
	else if (!strcasecmp("add", value))
		*item = MISSING_ADD;
	else
		return -1;
	return 0;
}

void trailer_conf_set(enum trailer_where where,
		      enum trailer_if_exists if_exists,
		      enum trailer_if_missing if_missing,
		      struct trailer_conf *conf)
{
	if (where != WHERE_DEFAULT)
		conf->where = where;
	if (if_exists != EXISTS_DEFAULT)
		conf->if_exists = if_exists;
	if (if_missing != MISSING_DEFAULT)
		conf->if_missing = if_missing;
}

struct trailer_conf *new_trailer_conf(void)
{
	struct trailer_conf *new = xcalloc(1, sizeof(*new));
	return new;
}

void duplicate_trailer_conf(struct trailer_conf *dst,
			    const struct trailer_conf *src)
{
	*dst = *src;
	dst->key_alias = xstrdup_or_null(src->key_alias);
	dst->key = xstrdup_or_null(src->key);
	dst->command = xstrdup_or_null(src->command);
	dst->cmd = xstrdup_or_null(src->cmd);
}

static struct trailer_template *get_or_add_template_by(const char *key_alias)
{
	struct list_head *pos;
	struct trailer_template *template;

	/* Look up template with same key_alias */
	list_for_each(pos, &templates_from_conf) {
		template = list_entry(pos, struct trailer_template, list);
		if (!strcasecmp(template->conf.key_alias, key_alias))
			return template;
	}

	/* Template does not already exist; create it. */
	CALLOC_ARRAY(template, 1);
	duplicate_trailer_conf(&template->conf, &default_trailer_conf);
	template->conf.key_alias = xstrdup(key_alias);
	template->target = NULL;

	list_add_tail(&template->list, &templates_from_conf);

	return template;
}

enum trailer_info_type { TRAILER_KEY, TRAILER_COMMAND, TRAILER_CMD,
			TRAILER_WHERE, TRAILER_IF_EXISTS, TRAILER_IF_MISSING };

static struct {
	const char *name;
	enum trailer_info_type type;
} trailer_config_items[] = {
	{ "key", TRAILER_KEY },
	{ "command", TRAILER_COMMAND },
	{ "cmd", TRAILER_CMD },
	{ "where", TRAILER_WHERE },
	{ "ifexists", TRAILER_IF_EXISTS },
	{ "ifmissing", TRAILER_IF_MISSING }
};

static int git_trailer_config_general(const char *opt, const char *setting,
				      const struct config_context *ctx UNUSED,
				      void *cb UNUSED)
{
	const char *trailer, *variable_name;

	if (!skip_prefix(opt, "trailer.", &trailer))
		return 0;

	variable_name = strrchr(trailer, '.');
	if (!variable_name) {
		if (!strcmp(trailer, "where")) {
			if (trailer_set_where(&default_trailer_conf.where,
					      setting) < 0)
				warning(_("invalid setting '%s' for option '%s'"),
					setting, opt);
		} else if (!strcmp(trailer, "ifexists")) {
			if (trailer_set_if_exists(&default_trailer_conf.if_exists,
						  setting) < 0)
				warning(_("invalid setting '%s' for option '%s'"),
					setting, opt);
		} else if (!strcmp(trailer, "ifmissing")) {
			if (trailer_set_if_missing(&default_trailer_conf.if_missing,
						   setting) < 0)
				warning(_("invalid setting '%s' for option '%s'"),
					setting, opt);
		} else if (!strcmp(trailer, "separators")) {
			if (!setting)
				return config_error_nonbool(opt);
			separators = xstrdup(setting);
		}
	}
	return 0;
}

static int git_trailer_config_by_key_alias(const char *opt, const char *setting,
					   const struct config_context *ctx UNUSED,
					   void *cb UNUSED)
{
	const char *trailer, *variable_name;
	struct trailer_template *template;
	struct trailer_conf *conf;
	char *key_alias = NULL;
	enum trailer_info_type type;
	int i;

	if (!skip_prefix(opt, "trailer.", &trailer))
		return 0;

	variable_name = strrchr(trailer, '.');
	if (!variable_name)
		return 0;

	variable_name++;
	for (i = 0; i < ARRAY_SIZE(trailer_config_items); i++) {
		if (strcmp(trailer_config_items[i].name, variable_name))
			continue;
		key_alias = xstrndup(trailer,  variable_name - trailer - 1);
		type = trailer_config_items[i].type;
		break;
	}

	if (!key_alias)
		return 0;

	template = get_or_add_template_by(key_alias);
	conf = &template->conf;
	free(key_alias);

	switch (type) {
	case TRAILER_KEY:
		if (conf->key)
			warning(_("option '%s' set more than once"), opt);
		if (!setting)
			return config_error_nonbool(opt);
		conf->key = xstrdup(setting);
		break;
	case TRAILER_COMMAND:
		if (conf->command)
			warning(_("option '%s' set more than once"), opt);
		if (!setting)
			return config_error_nonbool(opt);
		conf->command = xstrdup(setting);
		break;
	case TRAILER_CMD:
		if (conf->cmd)
			warning(_("option '%s' set more than once"), opt);
		if (!setting)
			return config_error_nonbool(opt);
		conf->cmd = xstrdup(setting);
		break;
	case TRAILER_WHERE:
		if (trailer_set_where(&conf->where, setting))
			warning(_("invalid setting '%s' for option '%s'"),
				setting, opt);
		break;
	case TRAILER_IF_EXISTS:
		if (trailer_set_if_exists(&conf->if_exists, setting))
			warning(_("invalid setting '%s' for option '%s'"),
				setting, opt);
		break;
	case TRAILER_IF_MISSING:
		if (trailer_set_if_missing(&conf->if_missing, setting))
			warning(_("invalid setting '%s' for option '%s'"),
				setting, opt);
		break;
	default:
		BUG("trailer.c: unhandled type %d", type);
	}
	return 0;
}

void trailer_config_init(void)
{
	if (configured)
		return;

	/* Default config must be setup first */
	default_trailer_conf.where = WHERE_END;
	default_trailer_conf.if_exists = EXISTS_ADD_IF_DIFFERENT_NEIGHBOR;
	default_trailer_conf.if_missing = MISSING_ADD;
	git_config(git_trailer_config_general, NULL);
	git_config(git_trailer_config_by_key_alias, NULL);
	configured = 1;
}

static const char *key_or_key_alias_from(struct trailer_template *template, char *tok)
{
	if (template->conf.key)
		return template->conf.key;
	if (tok)
		return tok;
	return template->conf.key_alias;
}

static int key_matches_template(const char *key,
				struct trailer_template *template,
				size_t key_len)
{
	if (!strncasecmp(key, template->conf.key_alias, key_len))
		return 1;
	return template->conf.key ? !strncasecmp(key, template->conf.key, key_len) : 0;
}

/*
 * If the given line is of the form
 * "<key><optional whitespace><separator>..." or "<separator>...", return the
 * location of the separator. Otherwise, return -1.  The optional whitespace
 * is allowed there primarily to allow things like "Bug #43" where <key> is
 * "Bug" and <separator> is "#".
 *
 * The separator-starts-line case (in which this function returns 0) is
 * distinguished from the non-well-formed-line case (in which this function
 * returns -1) because some callers of this function need such a distinction.
 */
ssize_t find_separator(const char *trailer_string, const char *separators)
{
	int whitespace_found = 0;
	const char *c;
	for (c = trailer_string; *c; c++) {
		if (strchr(separators, *c))
			return c - trailer_string;
		if (!whitespace_found && (isalnum(*c) || *c == '-'))
			continue;
		if (c != trailer_string && (*c == ' ' || *c == '\t')) {
			whitespace_found = 1;
			continue;
		}
		break;
	}
	return -1;
}

/*
 * Obtain the key, value, and conf from the given trailer.
 *
 * The conf needs special handling. We first read hardcoded defaults, and
 * override them if we find a matching trailer configuration.
 *
 * separator_pos must not be 0, since the key cannot be an empty string.
 *
 * If separator_pos is -1, interpret the whole trailer as a key.
 */
void parse_trailer(const char *trailer_string, ssize_t separator_pos,
		   struct strbuf *key, struct strbuf *val,
		   const struct trailer_conf **conf)
{
	struct trailer_template *template;
	size_t key_len;
	struct list_head *pos;

	if (separator_pos != -1) {
		strbuf_add(key, trailer_string, separator_pos);
		strbuf_trim(key);
		strbuf_addstr(val, trailer_string + separator_pos + 1);
		strbuf_trim(val);
	} else {
		strbuf_addstr(key, trailer_string);
		strbuf_trim(key);
	}

	/* Lookup if the key matches something in the config */
	key_len = key_len_without_separator(key->buf, key->len);
	if (conf)
		*conf = &default_trailer_conf;
	list_for_each(pos, &templates_from_conf) {
		template = list_entry(pos, struct trailer_template, list);
		if (key_matches_template(key->buf, template, key_len)) {
			char *key_buf = strbuf_detach(key, NULL);
			if (conf)
				*conf = &template->conf;
			strbuf_addstr(key, key_or_key_alias_from(template, key_buf));
			free(key_buf);
			break;
		}
	}
}

static struct trailer *add_trailer(struct list_head *trailers, char *key,
					     char *val)
{
	struct trailer *trailer = xcalloc(1, sizeof(*trailer));
	trailer->key = key;
	trailer->value = val;
	list_add_tail(&trailer->list, trailers);
	return trailer;
}

void add_trailer_template(char *key, char *val, const struct trailer_conf *conf,
			  struct list_head *templates)
{
	struct trailer_template *template = xcalloc(1, sizeof(*template));
	template->key = key;
	template->value = val;
	duplicate_trailer_conf(&template->conf, conf);
	list_add_tail(&template->list, templates);
}

void parse_trailer_templates_from_config(struct list_head *config_head)
{
	struct trailer_template *template;
	struct list_head *pos;

	/*
	 * Get configured templates with a ".command" option.
	 *
	 * NEEDSWORK: If the interpret-trailers builtin sees a
	 * "trailer.foo.command = ..." setting, then the "foo" trailer will
	 * always be inserted, even if "--trailer foo" is not provided.
	 * Considering how ".command" is deprecated, it is a bit strange to see
	 * it getting special treatment like this over ".cmd". Instead, we
	 * should add a new option that explicitly lets the user decide if the
	 * configured trailer should always be added automatically, or if it
	 * should only be added if "--trailer foo" is provided (default).
	 * Then we can collect configured trailers that have either ".command"
	 * or ".cmd" below, instead of just ".command".
	 */
	list_for_each(pos, &templates_from_conf) {
		template = list_entry(pos, struct trailer_template, list);
		if (template->conf.command)
			add_trailer_template(xstrdup(key_or_key_alias_from(template,
									   NULL)),
					     xstrdup(""), &template->conf, config_head);
	}
}

static const char *next_line(const char *str)
{
	const char *nl = strchrnul(str, '\n');
	return nl + !!*nl;
}

/*
 * Return the position of the start of the last line. If len is 0, return -1.
 */
static ssize_t last_line(const char *buf, size_t len)
{
	ssize_t i;
	if (len == 0)
		return -1;
	if (len == 1)
		return 0;
	/*
	 * Skip the last character (in addition to the null terminator),
	 * because if the last character is a newline, it is considered as part
	 * of the last line anyway.
	 */
	i = len - 2;

	for (; i >= 0; i--) {
		if (buf[i] == '\n')
			return i + 1;
	}
	return 0;
}

/*
 * Find the end of the log message as an offset from the start of the input
 * (where callers of this function are interested in looking for a trailers
 * block in the same input). We have to consider two categories of content that
 * can come at the end of the input which we want to ignore (because they don't
 * belong in the log message):
 *
 * (1) the "patch part" which begins with a "---" divider and has patch
 * information (like the output of git-format-patch), and
 *
 * (2) any trailing comment lines, blank lines like in the output of "git
 * commit -v", or stuff below the "cut" (scissor) line.
 *
 * As a formula, the situation looks like this:
 *
 *     INPUT = LOG MESSAGE + IGNORED
 *
 * where IGNORED can be either of the two categories described above. It may be
 * that there is nothing to ignore. Now it may be the case that the LOG MESSAGE
 * contains a trailer block, but that's not the concern of this function.
 */
static size_t find_end_of_log_message(const char *input, int no_divider)
{
	size_t end;
	const char *s;

	/* Assume the naive end of the input is already what we want. */
	end = strlen(input);

	if (no_divider)
		return end;

	/* Optionally skip over any patch part ("---" line and below). */
	for (s = input; *s; s = next_line(s)) {
		const char *v;

		if (skip_prefix(s, "---", &v) && isspace(*v)) {
			end = s - input;
			break;
		}
	}

	/* Skip over other ignorable bits. */
	return end - ignored_log_message_bytes(input, end);
}

/*
 * Return the position of the first trailer line or len if there are no
 * trailers.
 */
static size_t find_trailer_block_start(const char *buf, size_t len)
{
	const char *s;
	ssize_t end_of_title, l;
	int only_spaces = 1;
	int recognized_prefix = 0, trailer_lines = 0, non_trailer_lines = 0;
	/*
	 * Number of possible continuation lines encountered. This will be
	 * reset to 0 if we encounter a trailer (since those lines are to be
	 * considered continuations of that trailer), and added to
	 * non_trailer_lines if we encounter a non-trailer (since those lines
	 * are to be considered non-trailers).
	 */
	int possible_continuation_lines = 0;

	/* The first paragraph is the title and cannot be trailers */
	for (s = buf; s < buf + len; s = next_line(s)) {
		if (s[0] == comment_line_char)
			continue;
		if (is_blank_line(s))
			break;
	}
	end_of_title = s - buf;

	/*
	 * Get the start of the trailers by looking starting from the end for a
	 * blank line before a set of non-blank lines that (i) are all
	 * trailers, or (ii) contains at least one Git-generated trailer and
	 * consists of at least 25% configured trailers.
	 */
	for (l = last_line(buf, len);
	     l >= end_of_title;
	     l = last_line(buf, l)) {
		const char *bol = buf + l;
		const char **p;
		ssize_t separator_pos;

		if (bol[0] == comment_line_char) {
			non_trailer_lines += possible_continuation_lines;
			possible_continuation_lines = 0;
			continue;
		}
		if (is_blank_line(bol)) {
			if (only_spaces)
				continue;
			non_trailer_lines += possible_continuation_lines;
			if (recognized_prefix &&
			    trailer_lines * 3 >= non_trailer_lines)
				return next_line(bol) - buf;
			else if (trailer_lines && !non_trailer_lines)
				return next_line(bol) - buf;
			return len;
		}
		only_spaces = 0;

		for (p = git_generated_prefixes; *p; p++) {
			if (starts_with(bol, *p)) {
				trailer_lines++;
				possible_continuation_lines = 0;
				recognized_prefix = 1;
				goto continue_outer_loop;
			}
		}

		separator_pos = find_separator(bol, separators);
		if (separator_pos >= 1 && !isspace(bol[0])) {
			struct list_head *pos;

			trailer_lines++;
			possible_continuation_lines = 0;
			if (recognized_prefix)
				continue;
			/*
			 * The templates here are not used for actually
			 * adding trailers anywhere, but instead to help us
			 * identify trailer lines by comparing their keys with
			 * those found in configured templates.
			 */
			list_for_each(pos, &templates_from_conf) {
				struct trailer_template *template;
				template = list_entry(pos, struct trailer_template, list);
				if (key_matches_template(bol, template,
							 separator_pos)) {
					recognized_prefix = 1;
					break;
				}
			}
		} else if (isspace(bol[0]))
			possible_continuation_lines++;
		else {
			non_trailer_lines++;
			non_trailer_lines += possible_continuation_lines;
			possible_continuation_lines = 0;
		}
continue_outer_loop:
		;
	}

	return len;
}

static int ends_with_blank_line(const char *buf, size_t len)
{
	ssize_t ll = last_line(buf, len);
	if (ll < 0)
		return 0;
	return is_blank_line(buf + ll);
}

static void unfold_value(struct strbuf *val)
{
	struct strbuf out = STRBUF_INIT;
	size_t i;

	strbuf_grow(&out, val->len);
	i = 0;
	while (i < val->len) {
		char c = val->buf[i++];
		if (c == '\n') {
			/* Collapse continuation down to a single space. */
			while (i < val->len && isspace(val->buf[i]))
				i++;
			strbuf_addch(&out, ' ');
		} else {
			strbuf_addch(&out, c);
		}
	}

	/* Empty lines may have left us with whitespace cruft at the edges */
	strbuf_trim(&out);

	/* output goes back to val as if we modified it in-place */
	strbuf_swap(&out, val);
	strbuf_release(&out);
}

static struct trailer_block *trailer_block_new(void)
{
	struct trailer_block *trailer_block = xcalloc(1, sizeof(*trailer_block));
	return trailer_block;
}

static struct trailer_block *trailer_block_get(const struct trailer_processing_options *opts,
					       const char *str)
{
	struct trailer_block *trailer_block = trailer_block_new();
	size_t end_of_log_message = 0, trailer_block_start = 0;
	struct strbuf **trailer_block_lines, **ptr;
	char **trailer_strings = NULL;
	size_t nr = 0, alloc = 0;
	char **last = NULL;

	trailer_config_init();

	end_of_log_message = find_end_of_log_message(str, opts->no_divider);
	trailer_block_start = find_trailer_block_start(str, end_of_log_message);

	trailer_block_lines = strbuf_split_buf(str + trailer_block_start,
					       end_of_log_message - trailer_block_start,
					       '\n',
					       0);
	for (ptr = trailer_block_lines; *ptr; ptr++) {
		if (last && isspace((*ptr)->buf[0])) {
			struct strbuf sb = STRBUF_INIT;
			strbuf_attach(&sb, *last, strlen(*last), strlen(*last));
			strbuf_addbuf(&sb, *ptr);
			*last = strbuf_detach(&sb, NULL);
			continue;
		}
		ALLOC_GROW(trailer_strings, nr + 1, alloc);
		trailer_strings[nr] = strbuf_detach(*ptr, NULL);
		last = find_separator(trailer_strings[nr], separators) >= 1
			? &trailer_strings[nr]
			: NULL;
		nr++;
	}
	strbuf_list_free(trailer_block_lines);

	trailer_block->blank_line_before_trailer = ends_with_blank_line(str,
									trailer_block_start);
	trailer_block->start = trailer_block_start;
	trailer_block->end = end_of_log_message;
	trailer_block->trailer_strings = trailer_strings;
	trailer_block->trailer_nr = nr;

	return trailer_block;
}


/*
 * Parse trailers in "str", populating the trailer_block info and "trailers"
 * linked list structure.
 */
struct trailer_block *parse_trailers(const struct trailer_processing_options *opts,
				     const char *str,
				     struct list_head *trailers)
{
	struct trailer_block *trailer_block;
	struct strbuf key = STRBUF_INIT;
	struct strbuf val = STRBUF_INIT;
	size_t i;

	trailer_block = trailer_block_get(opts, str);

	for (i = 0; i < trailer_block->trailer_nr; i++) {
		int separator_pos;
		char *trailer_string = trailer_block->trailer_strings[i];
		if (trailer_string[0] == comment_line_char)
			continue;
		separator_pos = find_separator(trailer_string, separators);
		if (separator_pos >= 1) {
			parse_trailer(trailer_string, separator_pos, &key, &val, NULL);
			if (opts->unfold)
				unfold_value(&val);
			add_trailer(trailers,
					 strbuf_detach(&key, NULL),
					 strbuf_detach(&val, NULL));
		} else if (!opts->only_trailers) {
			strbuf_addstr(&val, trailer_string);
			strbuf_strip_suffix(&val, "\n");
			add_trailer(trailers,
					 NULL,
					 strbuf_detach(&val, NULL));
		}
	}

	return trailer_block;
}

void free_trailers(struct list_head *trailers)
{
	struct list_head *pos, *p;
	list_for_each_safe(pos, p, trailers) {
		list_del(pos);
		free_trailer(list_entry(pos, struct trailer, list));
	}
}

void free_trailer_templates(struct list_head *trailer_templates)
{
	struct list_head *pos, *p;

	list_for_each_safe(pos, p, trailer_templates) {
		list_del(pos);
		free_template(list_entry(pos, struct trailer_template, list));
	}
}

size_t trailer_block_start(struct trailer_block *trailer_block)
{
	return trailer_block->start;
}

size_t trailer_block_end(struct trailer_block *trailer_block)
{
	return trailer_block->end;
}

int blank_line_before_trailer_block(struct trailer_block *trailer_block)
{
	return trailer_block->blank_line_before_trailer;
}

void trailer_block_release(struct trailer_block *trailer_block)
{
	size_t i;
	for (i = 0; i < trailer_block->trailer_nr; i++)
		free(trailer_block->trailer_strings[i]);
	free(trailer_block->trailer_strings);
	free(trailer_block);
}

void format_trailers(const struct trailer_processing_options *opts,
		     struct list_head *trailers,
		     struct strbuf *out)
{
	size_t origlen = out->len;
	struct list_head *pos;
	struct trailer *trailer;

	list_for_each(pos, trailers) {
		trailer = list_entry(pos, struct trailer, list);
		if (trailer->key) {
			struct strbuf key = STRBUF_INIT;
			struct strbuf val = STRBUF_INIT;
			strbuf_addstr(&key, trailer->key);
			strbuf_addstr(&val, trailer->value);

			/*
			 * Skip key/value pairs where the value was empty. This
			 * can happen from trailers specified without a
			 * separator, like `--trailer "Reviewed-by"` (no
			 * corresponding value).
			 */
			if (opts->trim_empty && !strlen(trailer->value))
				continue;

			if (!opts->filter || opts->filter(&key, opts->filter_data)) {
				if (opts->separator && out->len != origlen)
					strbuf_addbuf(out, opts->separator);
				if (!opts->value_only)
					strbuf_addbuf(out, &key);
				if (!opts->key_only && !opts->value_only) {
					if (opts->key_value_separator)
						strbuf_addbuf(out, opts->key_value_separator);
					else {
						char c = last_non_space_char(key.buf);
						if (c) {
							if (!strchr(separators, c))
								strbuf_addf(out, "%c ", separators[0]);
						}
					}
				}
				if (!opts->key_only)
					strbuf_addbuf(out, &val);
				if (!opts->separator)
					strbuf_addch(out, '\n');
			}
			strbuf_release(&key);
			strbuf_release(&val);

		} else if (!opts->only_trailers) {
			if (opts->separator && out->len != origlen) {
				strbuf_addbuf(out, opts->separator);
			}
			/* Print non-trailer line as is. */
			strbuf_addstr(out, trailer->value);
			if (opts->separator)
				strbuf_rtrim(out);
			else
				strbuf_addch(out, '\n');
		}
	}
}

void format_trailers_from_commit(const struct trailer_processing_options *opts,
				 const char *msg,
				 struct strbuf *out)
{
	LIST_HEAD(trailers);
	struct trailer_block *trailer_block = parse_trailers(opts, msg, &trailers);

	/* If we want the whole block untouched, we can take the fast path. */
	if (!opts->only_trailers && !opts->unfold && !opts->filter &&
	    !opts->separator && !opts->key_only && !opts->value_only &&
	    !opts->key_value_separator) {
		strbuf_add(out, msg + trailer_block->start,
			   trailer_block->end - trailer_block->start);
	} else
		format_trailers(opts, &trailers, out);

	free_trailers(&trailers);
	trailer_block_release(trailer_block);
}

void trailer_iterator_init(struct trailer_iterator *iter, const char *msg)
{
	struct trailer_processing_options opts = TRAILER_PROCESSING_OPTIONS_INIT;
	strbuf_init(&iter->key, 0);
	strbuf_init(&iter->val, 0);
	opts.no_divider = 1;
	iter->internal.trailer_block = trailer_block_get(&opts, msg);
	iter->internal.cur = 0;
}

int trailer_iterator_advance(struct trailer_iterator *iter)
{
	if (iter->internal.cur < iter->internal.trailer_block->trailer_nr) {
		char *trailer_string = iter->internal.trailer_block->trailer_strings[iter->internal.cur++];
		int separator_pos = find_separator(trailer_string, separators);
		iter->is_trailer = (separator_pos > 0);

		iter->raw = trailer_string;
		strbuf_reset(&iter->key);
		strbuf_reset(&iter->val);
		parse_trailer(trailer_string, separator_pos, &iter->key, &iter->val, NULL);
		return 1;
	}
	return 0;
}

void trailer_iterator_release(struct trailer_iterator *iter)
{
	trailer_block_release(iter->internal.trailer_block);
	strbuf_release(&iter->val);
	strbuf_release(&iter->key);
}
