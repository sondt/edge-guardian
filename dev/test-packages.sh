#!/usr/bin/env bash
# Build and thoroughly test the .deb, .rpm and Docker image on real Linux containers.
#   bash dev/test-packages.sh
# Tests the container's native arch (arm64 on Apple Silicon, amd64 elsewhere).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "######## building packages (0.1.0 + 0.1.1 for the upgrade test) ########"
bash dev/build-packages.sh 0.1.0 >/dev/null
bash dev/build-packages.sh 0.1.1 >/dev/null
echo "done."
echo

echo "######## .deb  (debian:12-slim) ########"
docker run --rm --privileged -v "$PWD:/repo" debian:12-slim bash /repo/dev/test-deb-inner.sh

echo
echo "######## .rpm  (rockylinux:9) ########"
docker run --rm --privileged -v "$PWD:/repo" rockylinux:9 bash /repo/dev/test-rpm-inner.sh

echo
echo "######## Docker image ########"
bash dev/test-docker-image.sh

echo
echo "######## ALL PACKAGE TESTS PASSED ########"
