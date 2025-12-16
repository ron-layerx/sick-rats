#!/usr/bin/env bash

set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORIGINAL_DIR=$(pwd)
cd $DIR

rm -rf $DIR/extensions

fd -I -e crx -x sh -c '
    PARENT_DIR=$(basename "$(dirname "{}")")
    TARGET_DIR="extensions/$PARENT_DIR"
    mkdir -p "$TARGET_DIR"
    unzip -o {} "*.js" "*.json" "*.html" "*.md" "*.mdx" "*.css" -d "$TARGET_DIR"
'

cd $ORIGINAL_DIR
