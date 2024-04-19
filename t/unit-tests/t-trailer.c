#include "test-lib.h"
#include "trailer.h"

static void t_trailer_iterator(const char *msg, size_t num_expected_trailers)
{
	struct trailer_iterator iter;
	size_t i = 0;

	trailer_iterator_init(&iter, msg);
	while (trailer_iterator_advance(&iter)) {
		i++;
	}
	trailer_iterator_release(&iter);

	check_uint(i, ==, num_expected_trailers);
}

static void run_t_trailer_iterator(void)
{
	static struct test_cases {
		const char *name;
		const char *msg;
		size_t num_expected_trailers;
	} tc[] = {
		{
			"empty input",
			"",
			0
		},
		{
			"no newline at beginning",
			"Fixes: a\n"
			"Acked-by: b\n"
			"Reviewed-by: c\n",
			0
		},
		{
			"newline at beginning",
			"\n"
			"Fixes: a\n"
			"Acked-by: b\n"
			"Reviewed-by: c\n",
			3
		},
		{
			"log message without body text",
			"subject: foo bar\n"
			"\n"
			"Fixes: a\n"
			"Acked-by: b\n"
			"Reviewed-by: c\n",
			3
		},
		{
			"log message with body text, without divider",
			"my subject\n"
			"\n"
			"my body which is long\n"
			"and contains some special\n"
			"chars like : = ? !\n"
			"hello\n"
			"\n"
			"Fixes: a\n"
			"Acked-by: b\n"
			"Reviewed-by: c\n"
			"Signed-off-by: d\n",
			4
		},
		{
			"log message with body text, without divider (second trailer block)",
			"my subject\n"
			"\n"
			"my body which is long\n"
			"and contains some special\n"
			"chars like : = ? !\n"
			"hello\n"
			"\n"
			"Fixes: a\n"
			"Acked-by: b\n"
			"Reviewed-by: c\n"
			"Signed-off-by: d\n"
			"\n"
			/*
			 * Because this is the last trailer block, it takes
			 * precedence over the first one encountered above.
			 */
			"Helped-by: a\n"
			"Signed-off-by: b\n",
			2
		},
		{
			"log message with body text, with divider",
			"my subject\n"
			"\n"
			"my body which is long\n"
			"and contains some special\n"
			"chars like : = ? !\n"
			"hello\n"
			"\n"
			"---\n"
			"\n"
			/*
			 * This trailer still counts because the iterator
			 * always ignores the divider. */
			"Signed-off-by: d\n",
			1
		},
	};

	for (int i = 0; i < sizeof(tc) / sizeof(tc[0]); i++) {
		TEST(t_trailer_iterator(tc[i].msg,
					tc[i].num_expected_trailers),
		     "%s", tc[i].name);
	}
}

int cmd_main(int argc, const char **argv)
{
	run_t_trailer_iterator();
	return test_done();
}
