#!/usr/bin/env bash

set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

rm -rf $DIR/objects.txt $DIR/artifacts $DIR/extensions
