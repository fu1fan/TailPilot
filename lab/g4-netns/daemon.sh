#!/usr/bin/env bash
# Invoked ONLY inside unshare --mount --propagation private and a network netns.
# Hide host DNS files and service sockets before the daemon can initialize DNS.
set -euo pipefail
role_dir=$1
shift
mount --bind "$role_dir/etc" /etc
mount --bind "$role_dir/run" /run
exec "$@"
