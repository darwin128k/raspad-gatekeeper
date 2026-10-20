#!/usr/bin/env bash
set -euo pipefail

CLANG_FORMAT="${CLANG_FORMAT:-}"
if [[ -z "${CLANG_FORMAT}" ]]; then
	if command -v clang-format >/dev/null 2>&1; then
		CLANG_FORMAT="$(command -v clang-format)"
	elif [[ -x /mnt/c/Program\ Files/Microsoft\ Visual\ Studio/2022/Enterprise/VC/Tools/Llvm/x64/bin/clang-format.exe ]]; then
		CLANG_FORMAT="/mnt/c/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/Tools/Llvm/x64/bin/clang-format.exe"
	else
		echo "clang-format not found" >&2
		exit 1
	fi
fi
echo "using ${CLANG_FORMAT}"
"${CLANG_FORMAT}" --version

fmt_tree() {
	local style_file="$1/.clang-format"
	shift
	if [[ ! -f "${style_file}" ]]; then
		echo "missing ${style_file}" >&2
		exit 1
	fi
	# Absolute style path for clang-format.exe (cwd may not match)
	local style_abs
	style_abs="$(cd "$(dirname "${style_file}")" && pwd)/.clang-format"
	mapfile -d '' files < <(find "$@" -type f \( -name '*.c' -o -name '*.h' -o -name '*.cpp' -o -name '*.hpp' \) -print0)
	if [[ ${#files[@]} -eq 0 ]]; then
		echo "no files: $*"
		return 0
	fi
	printf '%s\0' "${files[@]}" | xargs -0 -r "${CLANG_FORMAT}" -i "-style=file:${style_abs}"
	echo "formatted ${#files[@]} files under: $*"
}

fmt_tree /mnt/h/Projects/raspad-gatekeeper \
	/mnt/h/Projects/raspad-gatekeeper/include \
	/mnt/h/Projects/raspad-gatekeeper/src

fmt_tree /mnt/h/Projects/raspad-authum \
	/mnt/h/Projects/raspad-authum/include \
	/mnt/h/Projects/raspad-authum/src \
	/mnt/h/Projects/raspad-authum/examples \
	/mnt/h/Projects/raspad-authum/tests

fmt_tree /mnt/h/Projects/raspad-gatekeeper/lib/authum \
	/mnt/h/Projects/raspad-gatekeeper/lib/authum/include \
	/mnt/h/Projects/raspad-gatekeeper/lib/authum/src

fmt_tree /mnt/h/Projects/raspad-qproto-2.0.0 \
	/mnt/h/Projects/raspad-qproto-2.0.0/include \
	/mnt/h/Projects/raspad-qproto-2.0.0/src \
	/mnt/h/Projects/raspad-qproto-2.0.0/tests

fmt_tree /mnt/h/Projects/raspad-qproto-2.0.0/lib/authum \
	/mnt/h/Projects/raspad-qproto-2.0.0/lib/authum/include \
	/mnt/h/Projects/raspad-qproto-2.0.0/lib/authum/src

echo OK
