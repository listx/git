#ifndef TRAILER_H
#define TRAILER_H

#include "list.h"
#include "strbuf.h"

struct trailer_block;
struct trailer_conf;
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

struct trailer_conf *new_trailer_conf(void);
void duplicate_trailer_conf(struct trailer_conf *dst,
			    const struct trailer_conf *src);
const char *trailer_default_separators(void);
void trailer_add_arg_item(struct list_head *arg_head, char *tok, char *val,
			  const struct trailer_conf *conf);

struct process_trailer_options {
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

#define PROCESS_TRAILER_OPTIONS_INIT {0}

void parse_trailers_from_config(struct list_head *config_head);

void process_trailers_lists(struct list_head *head,
			    struct list_head *arg_head);

ssize_t find_separator(const char *line, const char *separators);

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
void parse_trailer(const char *line, ssize_t separator_pos,
		   struct strbuf *tok, struct strbuf *val,
		   const struct trailer_conf **);

struct trailer_block *parse_trailers(const struct process_trailer_options *,
				     const char *str,
				     struct list_head *trailer_objects);

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

/*
 * Return 1 if the trailer block had an extra newline (blank line) just before
 * it.
 */
int blank_line_before_trailer_block(struct trailer_block *);

/*
 * Free trailer_block struct.
 */
void trailer_block_release(struct trailer_block *);

void trailer_config_init(void);
void format_trailers(const struct process_trailer_options *,
		     struct list_head *trailers,
		     struct strbuf *out);
void free_trailers(struct list_head *);
void free_new_trailers(struct list_head *);
void free_trailer_conf(struct trailer_conf *);

/*
 * Convenience function to format the trailers from the commit msg "msg" into
 * the strbuf "out". Reuses format_trailers() internally.
 */
void format_trailers_from_commit(const struct process_trailer_options *,
				 const char *msg,
				 struct strbuf *out);

/*
 * An interface for iterating over the trailers found in a particular commit
 * message. Use like:
 *
 *   struct trailer_iterator iter;
 *   trailer_iterator_init(&iter, msg);
 *   while (trailer_iterator_advance(&iter))
 *      ... do something with iter.key and iter.val ...
 *   trailer_iterator_release(&iter);
 */
struct trailer_iterator {
	/*
	 * Raw line (e.g., "foo: bar baz") before being parsed as a trailer
	 * key/val pair as part of a trailer block (as the "key" and "val"
	 * fields below). If a line fails to parse as a trailer, then the "key"
	 * will be the entire line and "val" will be the empty string.
	 */
	const char *raw;
	struct strbuf key;
	struct strbuf val;

	/* private */
	struct {
		struct trailer_block *trailer_block;
		size_t cur;
	} internal;
};

/*
 * Initialize "iter" in preparation for walking over the trailers in the commit
 * message "msg". The "msg" pointer must remain valid until the iterator is
 * released.
 *
 * After initializing, note that key/val will not yet point to any trailer.
 * Call advance() to parse the first one (if any).
 */
void trailer_iterator_init(struct trailer_iterator *iter, const char *msg);

/*
 * Advance to the next trailer of the iterator. Returns 0 if there is no such
 * trailer, and 1 otherwise. The key and value of the trailer can be
 * fetched from the iter->key and iter->value fields (which are valid
 * only until the next advance).
 */
int trailer_iterator_advance(struct trailer_iterator *iter);

/*
 * Release all resources associated with the trailer iteration.
 */
void trailer_iterator_release(struct trailer_iterator *iter);

/*
 * Augment a file to add trailers to it by running git-interpret-trailers.
 * This calls run_command() and its return value is the same (i.e. 0 for
 * success, various non-zero for other errors). See run-command.h.
 */
int amend_file_with_trailers(const char *path, const struct strvec *trailer_args);

#endif /* TRAILER_H */
