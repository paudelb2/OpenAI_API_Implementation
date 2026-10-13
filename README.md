#!/usr/bin/env bash
set -uo pipefail

# resolve the REAL binwalk3 (next in PATH that isn't this shim)
self="$(readlink -f "$0")"; REAL=""
for c in $(which -a binwalk3 2>/dev/null); do
    [[ "$(readlink -f "$c")" != "$self" ]] && { REAL="$c"; break; }
done
: "${REAL:=/usr/bin/binwalk3}"
[[ -x "$REAL" ]] || { echo "[!] real binwalk3 not found" >&2; exit 127; }

# first existing file = target, rest = binwalk flags
target=""; args=()
for a in "$@"; do
    if [[ -z "$target" && -f "$a" ]]; then target="$a"; else args+=("$a"); fi
done

# not an S-record (by content) -> hand off untouched
if [[ -z "$target" ]] || ! head -c128 "$target" 2>/dev/null | grep -qE '^S[0-9]'; then
    exec "$REAL" "$@"
fi
command -v srec_cat >/dev/null || { echo "[!] srecord not installed"; exec "$REAL" "$@"; }

outdir="${target%.*}_rt"; mkdir -p "$outdir"
rm -f "$outdir"/image.bin "$outdir"/seg[0-9][0-9]_*.sre "$outdir"/manifest.txt 2>/dev/null

echo "[*] S-Record detected (binwalk3 shim)."
echo "================ S-RECORD MEMORY MAP (srec_info) ================"
srec_info "$target"
echo "================================================================"

entry=$(srec_info "$target" 2>/dev/null | grep -i 'Execution Start Address' | grep -oE '[0-9A-Fa-f]+' | tail -n1)
whole="$outdir/image.bin"
srec_cat "$target" -o "$whole" -binary 2>/dev/null
echo "[+] Whole image (address-preserving) -> $whole"

manifest="$outdir/manifest.txt"
printf '%-7s %-11s %-11s %-8s %s\n' "SEG" "START" "END" "BYTES" "NOTE" > "$manifest"
n=0
while IFS= read -r line; do
    start="${line%% - *}"; end="${line##* - }"
    [[ -z "$start" || -z "$end" ]] && continue
    comp="$outdir/seg$(printf '%02d' $n)_${start}.sre"
    srec_cat "$target" -crop "0x$start" "$((0x$end + 1))" -o "$comp" -motorola 2>/dev/null
    size=$(( 0x$end - 0x$start + 1 )); note=""
    if [[ -n "$entry" ]] && (( 16#$entry >= 16#$start && 16#$entry <= 16#$end )); then
        note="contains entry 0x$entry (bootloader candidate)"
    fi
    printf '%-7s 0x%-9s 0x%-9s %-8s %s\n' "seg$(printf '%02d' $n)" "$start" "$end" "$size" "$note" >> "$manifest"
    echo "[+] Component: $comp  (0x$start-0x$end)${note:+  <- $note}"
    n=$((n+1))
done < <(srec_info "$target" 2>/dev/null | grep -oE '[0-9A-Fa-f]{2,8} - [0-9A-Fa-f]{2,8}')
[[ "$n" -eq 1 ]] && echo "[!] Single contiguous segment: no gap-based split."
echo "[*] Manifest -> $manifest"

echo "[*] Real binwalk3 signature scan (flags: ${args[*]:-none}):"
"$REAL" "${args[@]}" "$whole"
echo "[*] Real binwalk3 entropy scan:"
"$REAL" -E "$whole" 2>/dev/null || echo "    (verify -E on your binwalk3 build)"
echo "[*] Output in: $outdir/"
