#!/usr/bin/env bash
# 用法: sshrun.sh "远程命令"
# 密码来源优先级：$VM_PASS > tools/vm/.vm_pass（本地文件，已 gitignore）
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
PLINK="${PLINK:-/c/Program Files/PuTTY/plink}"
HOST="${VM_HOST:-192.168.182.128}"
USER="${VM_USER:-lzf}"
HKEY="${VM_HOSTKEY:-SHA256:XsBzY39zcb2Yy3UPwdgACkC/vptU8iWPz0H8kFeWGnA}"
PASS="${VM_PASS:-$(cat "$DIR/.vm_pass" 2>/dev/null)}"
exec "$PLINK" -ssh -batch -hostkey "$HKEY" -l "$USER" -pw "$PASS" "$HOST" "$@"
