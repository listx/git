/*
 * Builtin "git interpret-trailers"
 *
 * Copyright (c) 2013, 2014 Christian Couder <chriscool@tuxfamily.org>
 *
 */

#include "builtin.h"
#include "gettext.h"
#include "parse-options.h"
#include "string-list.h"
#include "tempfile.h"
#include "trailer.h"
#include "config.h"

static const char * const git_interpret_trailers_usage[] = {
	N_("git interpret-trailers [--in-place] [--trim-empty]\n"
	   "                       [(--trailer (<key>|<keyAlias>)[(=|:)<value>])...]\n"
	   "                       [--parse] [<file>...]"),
	NULL
};

static enum trailer_where where;
static enum trailer_if_exists if_exists;
static enum trailer_if_missing if_missing;

static int option_parse_where(const struct option *opt,
			      const char *arg, int unset UNUSED)
{
	/* unset implies NULL arg, which is handled in our helper */
	int err = trailer_set_where(opt->value, arg);
	if (err)
		return error(_("unknown value '%s' for flag '%s'"),
			     arg, "--where");
	return 0;
}

static int option_parse_if_exists(const struct option *opt,
				  const char *arg, int unset UNUSED)
{
	/* unset implies NULL arg, which is handled in our helper */
	int err = trailer_set_if_exists(opt->value, arg);
	if (err)
		return error(_("unknown value '%s' for flag '%s'"),
			     arg, "--if-exists");
	return 0;
}

static int option_parse_if_missing(const struct option *opt,
				   const char *arg, int unset UNUSED)
{
	/* unset implies NULL arg, which is handled in our helper */
	int err = trailer_set_if_missing(opt->value, arg);
	if (err)
		return error(_("unknown value '%s' for flag '%s'"),
			     arg, "--if-missing");
	return 0;
}

static char *cl_separators;
static struct trailer_subsystem_conf *tsc;

/*
 * Interpret "--trailer ..." as trailer templates (trailers we want to add into
 * the input text).
 */
static int option_parse_trailer_template(const struct option *opt,
					 const char *arg, int unset)
{
	struct list_head *templates = opt->value;
	struct trailer_conf *conf_current;
	struct trailer *trailer;

	if (unset) {
		free_trailer_templates(templates);
		return 0;
	}

	if (!arg)
		return -1;

	trailer = parse_trailer(arg, cl_separators, 0);
	if (get_trailer_type(trailer) != TRAILER_OK) {
		struct strbuf sb = STRBUF_INIT;
		strbuf_addstr(&sb, arg);
		strbuf_trim(&sb);
		error(_("invalid --trailer argument '%.*s'"),
			(int) sb.len, sb.buf);
		strbuf_release(&sb);
		free_trailer(trailer);
		return 0;
	}

	/*
	 * The parsed trailer "key" may actually be a key alias. Check if we
	 * have any configured key aliases that match, and if so, grab those
	 * trailer configurations to populate conf_current.
	 */
	conf_current = get_matching_trailer_conf(tsc, trailer);

	/*
	 * Override conf_current with settings specified via CLI flags.
	 */
	trailer_conf_set(where, if_exists, if_missing, conf_current);

	add_trailer_template(trailer, conf_current, templates);
	free(conf_current);
	free_trailer(trailer);
	return 0;
}

static int parse_opt_parse(const struct option *opt, const char *arg,
			   int unset)
{
	struct trailer_processing_options *v = opt->value;
	v->only_trailers = 1;
	v->only_input = 1;
	v->unfold = 1;
	BUG_ON_OPT_NEG(unset);
	BUG_ON_OPT_ARG(arg);
	return 0;
}

static struct tempfile *trailers_tempfile;

static FILE *create_in_place_tempfile(const char *file)
{
	struct stat st;
	struct strbuf filename_template = STRBUF_INIT;
	const char *tail;
	FILE *outfile;

	if (stat(file, &st))
		die_errno(_("could not stat %s"), file);
	if (!S_ISREG(st.st_mode))
		die(_("file %s is not a regular file"), file);
	if (!(st.st_mode & S_IWUSR))
		die(_("file %s is not writable by user"), file);

	/* Create temporary file in the same directory as the original */
	tail = strrchr(file, '/');
	if (tail)
		strbuf_add(&filename_template, file, tail - file + 1);
	strbuf_addstr(&filename_template, "git-interpret-trailers-XXXXXX");

	trailers_tempfile = xmks_tempfile_m(filename_template.buf, st.st_mode);
	strbuf_release(&filename_template);
	outfile = fdopen_tempfile(trailers_tempfile, "w");
	if (!outfile)
		die_errno(_("could not open temporary file"));

	return outfile;
}

static void read_from(const char *file, struct strbuf *out)
{
	if (file) {
		if (strbuf_read_file(out, file, 0) < 0)
			die_errno(_("could not read input file '%s'"), file);
	} else {
		if (strbuf_read(out, fileno(stdin), 0) < 0)
			die_errno(_("could not read from stdin"));
	}
}

/*
 * Parse the input file for trailers. Then add new trailers (with "templates")
 * to the trailers already in the input.
 */
static void interpret_trailers(const struct trailer_processing_options *opts,
			       struct list_head *templates,
			       const char *file)
{
	struct strbuf input = STRBUF_INIT;
	struct strbuf tb = STRBUF_INIT;
	struct trailer_block *trailer_block;
	FILE *outfile = stdout;

	read_from(file, &input);

	if (opts->in_place)
		outfile = create_in_place_tempfile(file);

	trailer_block = parse_trailer_block(opts, input.buf);

	/* Print the lines before the trailer block */
	if (!opts->only_trailers)
		fwrite(input.buf, 1, trailer_block_start(trailer_block), outfile);

	if (!opts->only_trailers && !blank_line_before_trailer_block(trailer_block))
		fprintf(outfile, "\n");


	if (!opts->only_input)
		apply_trailer_templates(templates, trailer_block);

	/* Print trailer block. */
	format_trailers(opts, trailer_block, &tb);
	fwrite(tb.buf, 1, tb.len, outfile);
	strbuf_release(&tb);

	/* Print the lines after the trailer block as is */
	if (!opts->only_trailers)
		fwrite(input.buf + trailer_block_end(trailer_block),
		       1, input.len - trailer_block_end(trailer_block), outfile);
	trailer_block_release(trailer_block);

	if (opts->in_place)
		if (rename_tempfile(&trailers_tempfile, file))
			die_errno(_("could not rename temporary file to %s"), file);

	strbuf_release(&input);
}

int cmd_interpret_trailers(int argc, const char **argv, const char *prefix)
{
	struct trailer_processing_options opts = TRAILER_PROCESSING_OPTIONS_INIT;
	LIST_HEAD(configured_templates);
	LIST_HEAD(templates);

	struct option options[] = {
		OPT_BOOL(0, "in-place", &opts.in_place, N_("edit files in place")),
		OPT_BOOL(0, "trim-empty", &opts.trim_empty, N_("trim empty trailers")),

		OPT_CALLBACK(0, "where", &where, N_("placement"),
			     N_("where to place the new trailer"), option_parse_where),
		OPT_CALLBACK(0, "if-exists", &if_exists, N_("action"),
			     N_("action if trailer already exists"), option_parse_if_exists),
		OPT_CALLBACK(0, "if-missing", &if_missing, N_("action"),
			     N_("action if trailer is missing"), option_parse_if_missing),

		OPT_BOOL(0, "only-trailers", &opts.only_trailers, N_("output only the trailers")),
		OPT_BOOL(0, "only-input", &opts.only_input, N_("do not apply trailer.* configuration variables")),
		OPT_BOOL(0, "unfold", &opts.unfold, N_("reformat multiline trailer values as single-line values")),
		OPT_CALLBACK_F(0, "parse", &opts, NULL, N_("alias for --only-trailers --only-input --unfold"),
			PARSE_OPT_NOARG | PARSE_OPT_NONEG, parse_opt_parse),
		OPT_BOOL(0, "no-divider", &opts.no_divider, N_("do not treat \"---\" as the end of input")),
		OPT_CALLBACK(0, "trailer", &templates, N_("trailer"),
				N_("trailer(s) to add"), option_parse_trailer_template),
		OPT_END()
	};

	git_config(git_default_config, NULL);
	tsc = trailer_subsystem_init();
	opts.tsc = tsc;

	if (!opts.only_input) {
		get_independent_trailer_templates_from(tsc, &configured_templates);
	}

	/*
	* In command-line arguments, '=' is accepted (in addition to the
	* separators that are defined).
	*/
	cl_separators = xstrfmt("=%s", trailer_default_separators(tsc));

	argc = parse_options(argc, argv, prefix, options,
			     git_interpret_trailers_usage, 0);

	free(cl_separators);

	if (opts.only_input && !list_empty(&templates))
		usage_msg_opt(
			_("--trailer with --only-input does not make sense"),
			git_interpret_trailers_usage,
			options);

	list_splice(&configured_templates, &templates);

	if (argc) {
		int i;
		for (i = 0; i < argc; i++)
			interpret_trailers(&opts, &templates, argv[i]);
	} else {
		if (opts.in_place)
			die(_("no input file given for in-place editing"));
		interpret_trailers(&opts, &templates, NULL);
	}

	free_trailer_templates(&templates);

	return 0;
}
