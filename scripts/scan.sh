#!/usr/bin/env bash

set -e

usage() {
    echo "Usage: $0 <subcommand> [options]"
    echo ""
    echo "Subcommands:"
    echo "  bucket      Scan S3 bucket for secrets"
    echo "  filesystem  Scan filesystem extensions for secrets"
    echo ""
    echo "Examples:"
    echo "  $0 bucket"
    echo "  $0 filesystem"
    exit 1
}

if [ $# -eq 0 ]; then
    usage
fi

SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR=$(cd "$SCRIPTS/.." && pwd)
SUBCOMMAND=$1
shift

AWS_PROFILE=prod
eval $(aws configure export-credentials --profile prod --format env)

case "$SUBCOMMAND" in
bucket)
    trufflehog s3 --bucket prod-classy-fire-artifacts "$@"
    ;;
filesystem)
    if [ -d "$DIR/artifacts" ]; then
        echo "Artifacts directory already exists, skipping download"
    else
        $SCRIPTS/download.sh
    fi

    if [ -d "$DIR/extensions" ]; then
        echo "Extensions directory already exists, skipping unzip"
    else
        set +e
        $SCRIPTS/unzip.sh
        set -e
    fi

    trufflehog filesystem $DIR/extensions "$@"
    ;;
*)
    echo "Error: Unknown subcommand '$SUBCOMMAND'"
    echo ""
    usage
    ;;
esac
