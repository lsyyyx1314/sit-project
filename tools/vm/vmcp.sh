#!/usr/bin/env bash
# 用法: vmcp.sh <本地路径> <远程路径>
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
PSCP="${PSCP:-/c/Program Files/PuTTY/pscp}"
HOST="${VM_HOST:-192.168.182.128}"
USER="${VM_USER:-lzf}"
HKEY="${VM_HOSTKEY:-SHA256:XsBzY39zcb2Yy3UPwdgACkC/vptU8iWPz0H8kFeWGnA}"
PASS="${VM_PASS:-$(cat "$DIR/.vm_pass" 2>/dev/null)}"
exec "$PSCP" -batch -hostkey "$HKEY" -pw "$PASS" -r "$1" "$USER@$HOST:$2"
