#!/bin/sh
# Copyright (c) 2026 Mikko Tanner. All rights reserved.
# Licensed under the MIT License or the Apache License, Version 2.0.
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Time-boxed sweep of every fuzz target: fuzz/run-all.sh [seconds-per-target]
# (default 60). Seeds the corpus first when it is missing. A crash stops the
# sweep; its input lands in fuzz/artifacts/<target>/ — reproduce with
# `cargo +nightly fuzz run <target> <file>`.
#
# No sanitizer (-s none): the code under test is safe Rust, where ASan finds
# nothing, and dropping it runs the targets faster; debug assertions
# (overflow checks) stay on.
set -eu
cd "$(dirname "$0")/.."
secs=${1:-60}
[ -d fuzz/corpus ] || cargo run -q --example fuzz_seeds
cd fuzz
for target in $(cargo +nightly fuzz list); do
    echo "=== $target (${secs}s)"
    cargo +nightly fuzz run -s none "$target" -- -max_total_time="$secs" -print_final_stats=1 2>&1 \
        | grep -E '^(stat::number_of_executed_units|stat::peak_rss_mb|SUMMARY|==[0-9]+==)|panicked' || true
    # cargo fuzz exits non-zero on a crash, but grep hides it: check artifacts
    if [ -n "$(ls "artifacts/$target" 2>/dev/null)" ]; then
        echo "!!! $target: crash input(s) in fuzz/artifacts/$target/"
        exit 1
    fi
done
