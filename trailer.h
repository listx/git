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
struct strvec;

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

int trailer_set_where(const char *, enum trailer_where *);
int trailer_set_if_exists(const char *, enum trailer_if_exists *);
int trailer_set_if_missing(const char *, enum trailer_if_missing *);

void trailer_set_conf_where(enum trailer_where, struct trailer_conf *);
void trailer_set_conf_if_exists(enum trailer_if_exists, struct trailer_conf *);
void trailer_set_conf_if_missing(enum trailer_if_missing, struct trailer_conf *);

const char *trailer_default_separators(struct trailer_subsystem_conf *);
void add_trailer_template(const struct trailer *,
			  const struct trailer_conf *,
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
	int (*filter)(const char*, void *);
	void *filter_data;
};

#define TRAILER_PROCESSING_OPTIONS_INIT {0}

void get_independent_trailer_templates_from(struct trailer_subsystem_conf *,
					    struct list_head *out);

void apply_trailer_templates(struct list_head *templates,
			     struct trailer_block *);

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
	 *   - "(cherry picked from commit ...)" (Git-generated)
	 *   - "Signed-off-by: ..." (key and sep; could be Git-generated)
	 *
	 * NOTE: The separator is hardcoded to be ":". But it can be overridden
	 * with configuration. For Git-generated trailers, their parsing rules
	 * are very strict; for example, see parse_cherry_picked_from_commit().
	 */
	TRAILER_OK,
};

ssize_t find_separator(const char *trailer_string, const char *separators);

/*
 * Given some input string "str", return a pointer to an opaque trailer_block
 * structure. Also populate the trailer_objects list with parsed trailer
 * objects. Internally this calls trailer_info_get() to get the opaque pointer,
 * but does some extra work to populate the trailer_objects linked list.
 *
 * The opaque trailer_block pointer can be used to check the position of the
 * trailer block as offsets relative to the beginning of "str" in
 * trailer_block_start() and trailer_block_end().
 * blank_line_before_trailer_block() returns 1 if there is a blank line just
 * before the trailer block. All of these functions are useful for preserving
 * the input before and after the trailer block, if we were to write out the
 * original input (but with the trailer block itself modified); see
 * builtin/interpret-trailers.c for an example.
 *
 * For iterating through the parsed trailer block (if you don't care about the
 * position of the trailer block itself in the context of the larger string text
 * from which it was parsed), please see trailer_iterator_init() which uses the
 * trailer_block struct internally.
 *
 * Lastly, callers should call trailer_info_release() when they are done using
 * the opaque pointer.
 *
 * NOTE: Callers should treat both trailer_block and trailer_objects as
 * read-only items, because there is some overlap between the two (trailer_block
 * has "char **trailers" string array, and trailer_objects will have the same
 * data but as a linked list of trailer_item objects). This API does not perform
 * any synchronization between the two. In the future we should be able to
 * reduce the duplication and use just the linked list.
 */

struct trailer *parse_trailer(const char *s,
			      const char *separators,
			      int leading_whitespace_is_continuation);

enum trailer_type get_trailer_type(struct trailer *);

struct trailer_conf *get_matching_trailer_conf(const struct trailer_subsystem_conf *,
					       const struct trailer *);

struct trailer_block *trailer_block_new(void);
struct trailer_block *parse_trailer_block(const struct trailer_processing_options *,
					  const char *str);
int maybe_new_trailer_block(struct list_head *templates,
			    struct trailer_block *);

/*
 * Return the offset of the start of the trailer block. That is, 0 is the start
 * of the input ("str" in parse_trailers()) and some other positive number
 * indicates how many bytes we have to skip over before we get to the beginning
 * of the trailer block.
 */
size_t trailer_block_start(struct trailer_block *);

/*
 * Return the end of the trailer block, again relative to the start of the
 * input.
 */
size_t trailer_block_end(struct trailer_block *);

int trailer_block_empty(struct trailer_block *);
int trailer_block_growable(struct trailer_block *);

/*
 * Free trailer_block struct.
 */
void trailer_block_release(struct trailer_block *);

struct trailer_subsystem_conf *trailer_subsystem_init(void);
void format_trailer_block(const struct trailer_processing_options *,
			  const struct trailer_block *,
			  struct strbuf *out);
void free_trailers(struct list_head *);
void free_trailer_conf(struct trailer_conf *);
void free_trailer_templates(struct list_head *);
void free_trailer(struct trailer *);

/*
 * Convenience function to format the trailers from the commit msg "msg" into
 * the strbuf "out". Reuses format_trailer_block() internally.
 */
void format_trailer_block_from_commit(struct trailer_processing_options *,
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
 */
const char *trailer_iter_raw(struct trailer_iter *);
const char *trailer_iter_key(struct trailer_iter *);
const char *trailer_iter_val(struct trailer_iter *);

/*
 * Augment a file to add trailers to it by running git-interpret-trailers.
 * This calls run_command() and its return value is the same (i.e. 0 for
 * success, various non-zero for other errors). See run-command.h.
 */
int amend_file_with_trailers(const char *path, const struct strvec *trailer_args);

#endif /* TRAILER_H */
