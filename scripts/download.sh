#!/usr/bin/env bash

set -e

AWS_PROFILE=prod
COUNT=${1:-100}
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

rm -rf $DIR/objects.txt $DIR/artifacts
aws s3 ls prod-classy-fire-artifacts --profile prod --recursive | head -n $COUNT | awk '{print $4}' >objects.txt
cat objects.txt | xargs -P 10 -I {} aws s3 cp s3://prod-classy-fire-artifacts/{} artifacts/{} --profile prod
