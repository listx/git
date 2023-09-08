#!/bin/sh

test_description='Test git-std-lib compilation'

. ./test-lib.sh

test_expect_success 'stdlib-test compiles and runs' '
	"$GIT_BUILD_DIR"/t/stdlib-test
'

test_done
