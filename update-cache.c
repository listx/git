#include "cache.h"

static int cache_name_compare(const char *name1, int len1, const char *name2, int len2)
{
	int len = len1 < len2 ? len1 : len2;
	int cmp;

	cmp = memcmp(name1, name2, len);
	/* There is a mismatch in the first len bytes. */
	if (cmp)
		return cmp;
	/* The first len bytes are identical, so compare based on overall length. */
	if (len1 < len2)
		return -1;
	if (len1 > len2)
		return 1;
	/* The two names are identical. */
	return 0;
}

/**
 * This function helps us determine the index into the active_cache[] array for
 * a given cache_entry, based on its name. It's basically a hashing scheme
 * because we try to place the entry in the middle of the first and last
 * entries, if possible (instead of trying to put entries consecutively next to
 * each other, as a regular array would). It's essentially binary search.
 */
static int cache_name_pos(const char *name, int namelen)
{
	int first, last;

	first = 0;
	last = active_nr;
	while (last > first) {
		/* Try the middle position first. */
		int mid = (first + last) >> 1;
		struct cache_entry *ce = active_cache[mid];
		int cmp = cache_name_compare(name, namelen, (const char *)ce->name, ce->namelen);
		/**
		 * Return a negative number only if the name matches the ce->name
		 * exactly. This is important for remove_file_from_cache() below.
		 *
		 * We "encode" the index value into a negative number, while still
		 * taking into account the case where "mid" is 0. The -1 at the end
		 * ensures that we can also handle the mid == 0 case.
		 */
		if (!cmp)
			return -mid-1;
		if (cmp < 0) {
			last = mid;
			continue;
		}
		first = mid+1;
	}
	return first;
}

static int remove_file_from_cache(const char *path)
{
	int pos = cache_name_pos(path, strlen(path));
	/**
	 * Only perform the removal if the file we want to remove matches the
	 * name already found in the cache.
	 *
	 * If pos is negative, make it positive and subtract 1. E.g., if -6, then
	 * make it 5. This "decodes" it to an actual (natural) index number.
	 *
	 * Don't read too deeply into the algorithm below in the current state
	 * though, because it was refactored a few days later in
	 * 76e7f4ec485f24b167b76db046dc2ca4562debd4.
	 */
	if (pos < 0) {
		pos = -pos-1;
		active_nr--;
		if ((unsigned int)pos < active_nr)
			memmove(active_cache + pos, active_cache + pos + 1, (active_nr - pos - 1) * sizeof(struct cache_entry *));
	}
	return 0;
}

static int add_cache_entry(struct cache_entry *ce)
{
	int pos;

	pos = cache_name_pos((const char *)ce->name, ce->namelen);

	/* existing match? Just replace it */
	if (pos < 0) {
		active_cache[-pos-1] = ce;
		return 0;
	}

	/* Make sure the array is big enough .. */
	if (active_nr == active_alloc) {
		active_alloc = alloc_nr(active_alloc);
		active_cache = realloc(active_cache, active_alloc * sizeof(struct cache_entry *));
	}

	/* Add it in.. */
	active_nr++;
	if (active_nr > (unsigned int)pos)
		memmove(active_cache + pos + 1, active_cache + pos, (active_nr - pos - 1) * sizeof(ce));
	active_cache[pos] = ce;
	return 0;
}

/**
 * Finalize a cache_entry by actually computing its compressed contents' SHA1
 * signature (ce->sha1). "fd" is the file descriptor whose (compressed) contents
 * we want to turn into a blob (along with some metadata alonge the way). We
 * also write this compressed data into ".git/objects/dc/..." ("dc" is just an
 * example byte name, and there are 255 others).
 */
static int index_fd(int namelen, struct cache_entry *ce, int fd, struct stat *st)
{
	SHA_CTX c;
	z_stream stream;
	/**
	 * Here we add 200 bytes as padding. This is most likely a performance
	 * optimization for malloc(), similar to the 8-byte alignment we did in the
	 * cache_entry_size macro.
	 */
	int max_out_bytes = namelen + st->st_size + 200;
	void *out = malloc(max_out_bytes);
	void *metadata = malloc(namelen + 200);

	/**
	 * mmap() can return MAP_FAILED, which is defined as
	 *
	 *   #define MAP_FAILED  ((void *) -1)
	 *
	 * on glibc
	 * (https://github.com/bminor/glibc/blob/9e2ff880f3cbc0b4ec8505ad2ce4a1c92d7f6d56/misc/sys/mman.h#L44).
	 *
	 * Note that mmap() will fail if the given file descriptor is for a path
	 * that is empty (such as a directory or a file with 0 bytes in it).
	 */
	void *in = mmap(NULL, st->st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);

	if (!out || in == MAP_FAILED)
		return -1;

	memset(&stream, 0, sizeof(stream));
	deflateInit(&stream, Z_BEST_COMPRESSION);

	/*
	 * ASCII size + nul byte
	 */	
	stream.next_in = metadata;
	stream.avail_in = 1+sprintf(metadata, "blob %lu", (unsigned long) st->st_size);
	stream.next_out = out;
	stream.avail_out = max_out_bytes;
	while (deflate(&stream, 0) == Z_OK)
		/* nothing */;

	/*
	 * File content
	 */
	stream.next_in = in;
	stream.avail_in = st->st_size;
	while (deflate(&stream, Z_FINISH) == Z_OK)
		/*nothing */;

	deflateEnd(&stream);
	
	SHA1_Init(&c);
	SHA1_Update(&c, out, stream.total_out);
	SHA1_Final(ce->sha1, &c);

	return write_sha1_buffer(ce->sha1, out, stream.total_out);
}

static int add_file_to_cache(const char *path)
{
	int size, namelen;
	struct cache_entry *ce;
	struct stat st;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		/* Handle file deletions. */
		if (errno == ENOENT)
			return remove_file_from_cache(path);
		return -1;
	}
	if (fstat(fd, &st) < 0) {
		close(fd);
		return -1;
	}
	namelen = strlen(path);
	size = cache_entry_size(namelen);
	ce = malloc(size);
	memset(ce, 0, size);
	memcpy(ce->name, path, namelen);
	ce->ctime.sec = st.st_ctime;
	ce->ctime.nsec = st.st_ctim.tv_nsec;
	ce->mtime.sec = st.st_mtime;
	ce->mtime.nsec = st.st_mtim.tv_nsec;
	ce->st_dev = st.st_dev;
	ce->st_ino = st.st_ino;
	ce->st_mode = st.st_mode;
	ce->st_uid = st.st_uid;
	ce->st_gid = st.st_gid;
	ce->st_size = st.st_size;
	ce->namelen = namelen;

	/**
	 * Calculate the SHA1 of the file and also write its SHA1 object file to
	 * disk.
	 */
	if (index_fd(namelen, ce, fd, &st) < 0)
		return -1;

	return add_cache_entry(ce);
}

static int write_cache(int newfd, struct cache_entry **cache, int entries)
{
	SHA_CTX c;
	struct cache_header hdr;
	int i;

	hdr.signature = CACHE_SIGNATURE;
	hdr.version = 1;
	hdr.entries = entries;

	SHA1_Init(&c);
	SHA1_Update(&c, &hdr, offsetof(struct cache_header, sha1));
	for (i = 0; i < entries; i++) {
		struct cache_entry *ce = cache[i];
		int size = ce_size(ce);
		SHA1_Update(&c, ce, size);
	}
	SHA1_Final(hdr.sha1, &c);

	if (write(newfd, &hdr, sizeof(hdr)) != sizeof(hdr))
		return -1;

	for (i = 0; i < entries; i++) {
		struct cache_entry *ce = cache[i];
		int size = ce_size(ce);
		if (write(newfd, ce, size) != size)
			return -1;
	}
	return 0;
}		

/*
 * We fundamentally don't like some paths: we don't want
 * dot or dot-dot anywhere, and in fact, we don't even want
 * any other dot-files (.git or anything else). They
 * are hidden, for chist sake.
 *
 * Also, we don't want double slashes or slashes at the
 * end that can make pathnames ambiguous. 
 */
static int verify_path(char *path)
{
	char c;

	goto inside;
	for (;;) {
		if (c == '\0')
			return 1;
		if (c == '/') {
inside:
			c = *path++;
			if (c != '/' && c != '.' && c != '\0')
				continue;
			return 0;
		}
		c = *path++;
	}
}

/**
 * Give file paths to add to the .git/index (staging area). This is a primitive
 * "git add" that only understands entire files. This is also before .gitignore
 * files were implemented, so we ignore paths that have any hidden dot-files in
 * them at any point in their path hierarchy (see verify_path()).
 *
 * We cannot add directories either, only files (with actual contents!).
 */
int main(int argc, char **argv)
{
	int i, newfd, entries;

	entries = read_cache();
	if (entries < 0) {
		perror("cache corrupted");
		return -1;
	}

	newfd = open(".git/index.lock", O_RDWR | O_CREAT | O_EXCL, 0600);
	if (newfd < 0) {
		perror("unable to create new cachefile");
		return -1;
	}
	for (i = 1 ; i < argc; i++) {
		char *path = argv[i];
		if (!verify_path(path)) {
			fprintf(stderr, "Ignoring path %s\n", argv[i]);
			continue;
		}
		if (add_file_to_cache(path)) {
			fprintf(stderr, "Unable to add %s to database\n", path);
			goto out;
		}
	}
	if (!write_cache(newfd, active_cache, active_nr) && !rename(".git/index.lock", ".git/index"))
		return 0;
out:
	unlink(".git/index.lock");

	return 0;
}
