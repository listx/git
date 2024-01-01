#ifndef TRAILER_H
#define TRAILER_H

#include "list.h"
#include "strbuf.h"

struct trailer_subsystem_conf;
struct trailer_block;
struct trailer_conf;
struct trailer_iter;

enum trailer_where {
	WHERE_UNSPECIFIED,
	WHERE_END,
	WHERE_AFTER,
	WHERE_BEFORE,
	WHERE_START
};
enum trailer_if_exists {
	EXISTS_UNSPECIFIED,
	EXISTS_ADD_IF_DIFFERENT_NEIGHBOR,
	EXISTS_ADD_IF_DIFFERENT,
	EXISTS_ADD,
	EXISTS_REPLACE,
	EXISTS_DO_NOTHING
};
enum trailer_if_missing {
	MISSING_UNSPECIFIED,
	MISSING_ADD,
	MISSING_DO_NOTHING
};

int trailer_set_where(enum trailer_where *item, const char *value);
int trailer_set_if_exists(enum trailer_if_exists *item, const char *value);
int trailer_set_if_missing(enum trailer_if_missing *item, const char *value);

void trailer_conf_set_where(enum trailer_where where, struct trailer_conf *trailer_conf);
void trailer_conf_set_if_exists(enum trailer_if_exists if_exists, struct trailer_conf *trailer_conf);
void trailer_conf_set_if_missing(enum trailer_if_missing if_missing, struct trailer_conf *trailer_conf);
struct trailer_conf *new_trailer_conf(void);
void duplicate_conf(struct trailer_conf *dst, const struct trailer_conf *src);

const char *default_separators(struct trailer_subsystem_conf *tsc);

void add_trailer_injector(char *key, char *val, const struct trailer_conf *conf,
			  struct list_head *injectors);

struct trailer_processing_options {
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

void get_independent_trailer_injectors_from(struct trailer_subsystem_conf *tsc,
					    struct list_head *out);

void apply_trailer_injectors(struct list_head *injectors, struct list_head *trailers_head);

ssize_t find_separator(const char *trailer_string, const char *separators);

void parse_trailer(const char *trailer_string, ssize_t separator_pos,
		   struct trailer_subsystem_conf *tsc,
		   struct strbuf *key, struct strbuf *val,
		   const struct trailer_conf **conf);

struct trailer_block *parse_trailers(const char *str,
				     const struct trailer_processing_options *opts,
				     struct trailer_subsystem_conf *tsc,
				     struct list_head *trailers);

struct trailer_block *trailer_block_get(const char *str,
					const struct trailer_processing_options *opts,
					struct trailer_subsystem_conf *tsc);

size_t trailer_block_start(struct trailer_block *trailer_block);
size_t trailer_block_end(struct trailer_block *trailer_block);
int blank_line_before_trailer_block(struct trailer_block *trailer_block);

void trailer_block_release(struct trailer_block *trailer_block);

struct trailer_subsystem_conf *trailer_config_init(void);
void free_trailers(struct list_head *trailers);
void free_trailer_injectors(struct list_head *trailer_injectors);

void format_trailers(struct list_head *head,
		     const struct trailer_processing_options *opts,
		     struct trailer_subsystem_conf *tsc,
		     struct strbuf *out);
/*
 * Convenience function to format the trailers from the commit msg "msg" into
 * the strbuf "out". Reuses format_trailers internally.
 */
void format_trailers_from_commit(const char *msg,
				 const struct trailer_processing_options *opts,
				 struct strbuf *out);

/*
 * Initialize "iter" in preparation for walking over the trailers in the commit
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
int trailer_iter_advance(struct trailer_iter *iter);

/*
 * Release all resources associated with the trailer iteration.
 */
void trailer_iter_release(struct trailer_iter *iter);

int trailer_iter_is_trailer(struct trailer_iter *iter);
const char *trailer_iter_raw(struct trailer_iter *iter);
const char *trailer_iter_key(struct trailer_iter *iter);
const char *trailer_iter_val(struct trailer_iter *iter);

#endif /* TRAILER_H */
