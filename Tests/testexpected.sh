#!/bin/sh
set -e
cd $(dirname $(realpath $0))
/bin/sh -c "$1 $(grep -v '^#' $2)" | diff - $2.expected
