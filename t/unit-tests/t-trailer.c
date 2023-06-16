#include "test-lib.h"
#include "trailer.h"

/*
 * Wrapper that calls tests by automatically calculating the token's overall
 * length.
 * */
static void helper(void (*f)(const char *, size_t, size_t), const char *token,
		   size_t expected)
{
	f(token, strlen(token), expected);
}

static void t_token_len_without_separator(const char *token, size_t len,
					  size_t expected)
{
	size_t result;
	result = token_len_without_separator(token, len);
	check_uint(result, ==, expected);
}

static void t_after_or_end(enum trailer_where where, int expected)
{
	size_t result;
	result = after_or_end(where);
	check_int(result, ==, expected);
}


static void t_same_token(struct trailer_item *a, struct arg_item *b, int expected)
{
	size_t result;
	result = same_token(a, b);
	check_int(result, ==, expected);
}

void test_same_token()
{
	/*
	 * same_token should probably be renamed to same_token_prefix because that's
	 * how the code behaves. It also ignores case differences.
	 *
	 * FIXME: Does this mean that token keys must be a case-insensitive prefix
	 * of the full string? YES. Maybe we can relax this setting?
	 */
    struct trailer_item a = { .token = "foo" };
	TEST(t_same_token(&a, &{ .token = "food" }, 1), "same trailer_item token as arg_item token");
}

int cmd_main(int argc, const char **argv)
{
	test_same_token();

	TEST(t_after_or_end(WHERE_AFTER, 1), "accept WHERE_AFTER");
	TEST(t_after_or_end(WHERE_END, 1), "accept WHERE_END");
	TEST(t_after_or_end(WHERE_DEFAULT, 0), "reject WHERE_END");

	TEST(helper(t_token_len_without_separator, "Signed-off-by:", 13),
	     "token with trailing punctuation (colon)");
	TEST(helper(t_token_len_without_separator, "Signed-off-by", 13),
	     "token without trailing punctuation");
	TEST(helper(t_token_len_without_separator, "Foo bar:", 7),
	     "token with spaces with trailing punctuation (colon)");
	TEST(helper(t_token_len_without_separator, "Foo bar", 7),
	     "token with spaces without trailing punctuation");
	TEST(helper(t_token_len_without_separator, "-Foo bar:", 8),
	     "token with leading non-separator punctuation");
	TEST(helper(t_token_len_without_separator, "- Foo bar:", 9),
	     "token with leading non-separator punctuation");

	return test_done();
}
