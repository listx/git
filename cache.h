#ifndef CACHE_H
#define CACHE_H

#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>

#include <openssl/sha.h>
#include <zlib.h>

/*
 * Basic data structures for the directory cache
 *
 * NOTE NOTE NOTE! This is all in the native CPU byte format. It's
 * not even trying to be portable. It's trying to be efficient. It's
 * just a cache, after all.
 */

#define CACHE_SIGNATURE 0x44495243	/* "DIRC" */
struct cache_header {
	unsigned int signature;
	unsigned int version;
	unsigned int entries;
	unsigned char sha1[20];
};

/*
 * The "cache_time" is just the low 32 bits of the
 * time. It doesn't matter if it overflows - we only
 * check it for equality in the 32 bits we save.
 */
struct cache_time {
	unsigned int sec;
	unsigned int nsec;
};

/*
 * dev/ino/uid/gid/size are also just tracked to the low 32 bits
 * Again - this is just a (very strong in practice) heuristic that
 * the inode hasn't changed.
 */
struct cache_entry {
	struct cache_time ctime;
	struct cache_time mtime;
	unsigned int st_dev;
	unsigned int st_ino;
	unsigned int st_mode;
	unsigned int st_uid;
	unsigned int st_gid;
	unsigned int st_size;
	unsigned char sha1[20];
	unsigned short namelen;
	/**
	 * The "name" comes last because it's the path for a file and is of variable
	 * length. Putting it here makes computing the bytes needed for a
	 * cache_entry in the cache_entry_size macro.
	 */
	unsigned char name[0];
};

extern const char *sha1_file_directory;
extern struct cache_entry **active_cache;
extern unsigned int active_nr, active_alloc;

#define DB_ENVIRONMENT "SHA1_FILE_DIRECTORY"
#define DEFAULT_DB_ENVIRONMENT ".dircache/objects"

/**
 * Determine how many bytes a new cache_entry would _actually_ need (for
 * invoking malloc), because the 'name' member is of variable length (it is the
 * filepath that this cache_entry represents).
 *
 * The total bytes we need are:
 * 1. Use "offsetof" macro to calculate the static parts of the struct.
 * 2. Add the length of the path (namelen), in bytes.
 *
 * The above are technically enough, but they don't explain the "+ 8" and
 * masking with ~7 (11111000). This is done so that the total bytes is always
 * some multiple of 8. The "+ 8" pads 8 additional bytes to whatever the total
 * of steps 1 and 2 are. At this point we have "N*8 + remainder" bytes where
 * "remainder" could be 0 through 7. Then we mask it with ~7 (this discards any
 * value less <= 7) so that we can remove this useless remainder.
 */
#define cache_entry_size(namelen) ((offsetof(struct cache_entry,name) + (namelen) + 8) & ~7)
/**
 * Calculate the cache_entry_size of an existing (already-malloc-ed)
 * cache_entry.
 */
#define ce_size(ce) cache_entry_size((ce)->namelen)

#define alloc_nr(x) (((x)+16)*3/2)

/* Initialize the cache information */
extern int read_cache(void);

/* Return a statically allocated filename matching the sha1 signature */
extern char *sha1_file_name(unsigned char *sha1);

/* Write a memory buffer out to the sha file */
extern int write_sha1_buffer(unsigned char *sha1, void *buf, unsigned int size);

/* Read and unpack a sha1 file into memory, write memory to a sha1 file */
extern void * read_sha1_file(unsigned char *sha1, char *type, unsigned long *size);
extern int write_sha1_file(char *buf, unsigned len);

/* Convert to/from hex/sha1 representation */
extern int get_sha1_hex(char *hex, unsigned char *sha1);
extern char *sha1_to_hex(unsigned char *sha1);	/* static buffer! */

/* General helper functions */
extern void usage(const char *err);

#endif /* CACHE_H */
