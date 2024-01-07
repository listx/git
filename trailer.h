#ifndef TRAILER_H
#define TRAILER_H

#include "list.h"
#include "strbuf.h"

/*
 * trailer_subsystem_conf holds all settings found from parsing "trailer.*"
 * options. If there are "trailer.<keyAlias>.*" options, they are included in
 * here.
 */
struct trailer_subsystem_conf;
/*
 * trailer_conf holds all "trailer.<keyAlias>.*" options for the same
 * <keyAlias>.
 */
struct trailer_conf;

struct trailer_block;
struct trailer_iter;
struct trailer;

enum trailer_where {
	WHERE_DEFAULT,
	WHERE_END,
	WHERE_AFTER,
	WHERE_BEFORE,
	WHERE_START
};
enum trailer_if_exists {
	EXISTS_DEFAULT,
	EXISTS_ADD_IF_DIFFERENT_NEIGHBOR,
	EXISTS_ADD_IF_DIFFERENT,
	EXISTS_ADD,
	EXISTS_REPLACE,
	EXISTS_DO_NOTHING
};
enum trailer_if_missing {
	MISSING_DEFAULT,
	MISSING_ADD,
	MISSING_DO_NOTHING
};

int trailer_set_where(enum trailer_where *item, const char *value);
int trailer_set_if_exists(enum trailer_if_exists *item, const char *value);
int trailer_set_if_missing(enum trailer_if_missing *item, const char *value);

void trailer_conf_set(enum trailer_where where,
		      enum trailer_if_exists if_exists,
		      enum trailer_if_missing if_missing,
		      struct trailer_conf *conf);

const char *trailer_default_separators(struct trailer_subsystem_conf *tsc);

void add_trailer_template(const struct trailer *trailer,
			  const struct trailer_conf *conf,
			  struct list_head *templates);

struct trailer_processing_options {
	struct trailer_subsystem_conf *tsc;
	int in_place;
	int trim_empty;
	int only_trailers;
	int only_input;
	int unfold;
	int no_divider;
	int key_only;
	int value_only;
	const struct strbuf *separator;
	const struct strbuf *key_value_separator;
	int (*filter)(const struct strbuf *, void *);
	void *filter_data;
};

#define TRAILER_PROCESSING_OPTIONS_INIT {0}

void get_independent_trailer_templates_from(struct trailer_subsystem_conf *tsc,
					    struct list_head *out);

void apply_trailer_templates(struct list_head *templates,
			     struct trailer_block *trailer_block);

/*
 * The following represent the ways in which an arbitrary piece of text could be
 * parsed as (or not as) a trailer. A trailer requires a key. All types except
 * TRAILER_OK are "non-trailer" lines and lack any information about a key.
 */
enum trailer_type {
	/*
	 * TRAILER_UNINITIALIZED is not actually used anywhere directly. This is
	 * the default setting if we allocate (xcalloc) a new trailer and forget
	 * to do anything with it. That way the (brand new, unpopulated) trailer
	 * won't confusingly have TRAILER_COMMENT as its trailer_type.
	 */
	TRAILER_UNINITIALIZED,
	/*
	 * Example: "# commented line"
	 */
	TRAILER_COMMENT,

	/*
	 * Examples:
	 *
	 *   - "  indented line"
	 *   - "  key: value"    (looks like a trailer, but is still indented)
	 */
	TRAILER_INDENTED,

	/*
	 * This is a line that could not be parsed as a trailer with a key and
	 * value. After they are parsed, we have to reach into the "raw" member
	 * to print it back out during formatting. Examples:
	 *
	 *   - ""        (empty line)
	 *   - "foo bar" (no separator; "foo" could be a key, but " bar" is not
	 *                a value because there is no separator)
	 *   - "foo$bar" (no sep; "foo$bar" cannot be a key ($ is invalid),
	 *                and so "foo" could be a key but then "$bar" is junk)
	 *   - ":"       (sep found, but no key)
	 *   - ":val"    (sep found, but no key)
	 *   - "(cherry picked from commit 00000000)" (Git-generated line)
	 *
	 * NEEDSWORK: Make the "(cherry picked ...)" Git-generated line be
	 * parsed as TRAILER_OK with key "cherry picked from commit" and
	 * value "00000000".
	 */
	TRAILER_JUNK,

	/*
	 * Key found. Separator and value are optional (however, if a value does
	 * exist, then it may only come after a separator). Spaces may exist
	 * around the separator.
	 *
	 * Examples:
	 *
	 *   - "key"      (key without sep)
	 *   - "key:"     (key and sep)
	 *   - "key: "    (key and sep)
	 *   - "key #"    (key and sep)
	 *   - "foo: bar" (key and sep and value)
	 *   - "Signed-off-by: " (key and sep; also a Git-generated line)
	 *
	 * NOTE: The separator is hardcoded to be ":". But it can be overridden
	 * with configuration.
	 */
	TRAILER_OK,
};

ssize_t find_separator(const char *trailer_string, const char *separators);

struct trailer *parse_trailer(const char *s,
			      const char *separators,
			      int leading_whitespace_is_continuation);

enum trailer_type get_trailer_type(struct trailer *);

struct trailer_conf *get_matching_trailer_conf(const struct trailer_subsystem_conf *tsc,
					       const struct trailer *trailer);

struct trailer_block *parse_trailer_block(const struct trailer_processing_options *opts,
					  const char *str);

size_t trailer_block_start(struct trailer_block *);
size_t trailer_block_end(struct trailer_block *);
int blank_line_before_trailer_block(struct trailer_block *);

void trailer_block_release(struct trailer_block *);

struct trailer_subsystem_conf *trailer_subsystem_init(void);

void format_trailers(const struct trailer_processing_options *opts,
		     struct trailer_block *trailer_block,
		     struct strbuf *out);
void free_trailers(struct list_head *);
void free_trailer_templates(struct list_head *);
void free_trailer(struct trailer *);

/*
 * Convenience function to format the trailers from the commit msg "msg" into
 * the strbuf "out". Reuses format_trailers internally.
 */
void format_trailers_from_commit(struct trailer_processing_options *opts,
				 const char *msg,
				 struct strbuf *out);

/*
 * Initialize iterator for walking over the trailers in the commit
 * message "msg". The "msg" pointer must remain valid until the iterator is
 * released.
 *
 * After initializing, note that key/val will not yet point to any trailer.
 * Call advance() to parse the first one (if any).
 */
struct trailer_iter *trailer_iter_init(const char *msg);

/*
 * Advance to the next trailer of the iterator. Returns 0 if there is no such
 * trailer, and 1 otherwise. The key and value of the trailer can be
 * fetched from the iter->key and iter->value fields (which are valid
 * only until the next advance).
 */
int trailer_iter_advance(struct trailer_iter *);

/*
 * Release all resources associated with the trailer iteration.
 */
void trailer_iter_release(struct trailer_iter *);

/*
 * Getters for trailer iterator.
 *
 * trailer_iter_{raw,key,val} give access to the unparsed trailer, and the
 * parsed key and value.
 *
 * trailer_iter_is_trailer is true if the iterator is currently looking at a
 * trailer object that has a trailer line (key and value). A trailer object may
 * contain a non-trailer line, because a trailer block may have trailer and
 * non-trailer lines (only 25% or more must be trailer lines).
 */
const char *trailer_iter_raw(struct trailer_iter *);
const char *trailer_iter_key(struct trailer_iter *);
const char *trailer_iter_val(struct trailer_iter *);
int trailer_iter_is_trailer(struct trailer_iter *);

#endif /* TRAILER_H */
