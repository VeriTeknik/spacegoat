#!/bin/sh
# Checks the form of docs/yonetmelik-eslestirme.md. It cannot judge whether a row is true; it only refuses the
# mistakes a reader would be misled by: a compliance claim, a row without its article or its quote, a dead link.
# Usage: sh docs/check-mapping.sh [file]   (run from the repository root)
set -eu

doc="${1:-docs/yonetmelik-eslestirme.md}"
dir=$(dirname "$doc")
fail=0
say() {
  echo "$doc: $1"
  fail=1
}

if [ ! -f "$doc" ]; then
  echo "$doc: yok"
  exit 1
fi

# 1. No claim of conformity, in either language. The document says what a draft article asks and what the
#    software does; whether an organisation conforms is for that organisation and its auditor.
claims=$(grep -n -i -E 'uyumludur|uyumlu oldu|uyum sağlar|uyumluluğu sağla|sertifikalı|compliant|certified' "$doc" || true)
if [ -n "$claims" ]; then
  say "uyum ya da belge iddiası var:"
  echo "$claims"
fi

# 2. No em dash.
dashes=$(grep -n '—' "$doc" || true)
if [ -n "$dashes" ]; then
  say "em dash var:"
  echo "$dashes"
fi

# 3. Every row of the mapping table names its article and carries a quote from the draft.
#    The table sits between the two markers; its columns are
#    | Konu | Madde (taslak) | Taslak metni | SpaceGoat ne yapar | Kanıtı | Durum |
if ! grep -q '^<!-- eslestirme:basla -->$' "$doc" || ! grep -q '^<!-- eslestirme:bitir -->$' "$doc"; then
  say "eşleştirme tablosunun işaretleri yok"
else
  rows=$(awk '
    /^<!-- eslestirme:basla -->$/ { inside = 1; next }
    /^<!-- eslestirme:bitir -->$/ { inside = 0 }
    inside && /^\|/ {
      n = split($0, cell, "|")
      if (cell[2] ~ /^ *Konu *$/ || cell[2] ~ /^ *-+ *$/) next
      count++
      if (n != 8) { printf "satır %d: 6 sütun bekleniyor\n", NR; next }
      if (cell[3] !~ /md\. [0-9]/) printf "satır %d: madde numarası yok\n", NR
      if (cell[4] !~ /"[^"]+"/) printf "satır %d: taslaktan alıntı yok\n", NR
      if (cell[7] !~ /^ *(var|kısmen|planlı|yok) *$/) printf "satır %d: durum var, kısmen, planlı ya da yok olmalı\n", NR
    }
    END { if (count == 0) print "tabloda satır yok" }
  ' "$doc")
  if [ -n "$rows" ]; then
    say "eşleştirme tablosu:"
    echo "$rows"
  fi
fi

# 4. Every relative link points at a file that is in the repository.
links=$(grep -o -E '\]\([^)]+\)' "$doc" | sed -E 's/^\]\(//; s/\)$//' | grep -v -E '^(https?:|mailto:|#)' || true)
for link in $links; do
  path=${link%%#*}
  if [ ! -e "$dir/$path" ]; then
    say "bağlantı depoda yok: $link"
  fi
done

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "ok $doc"
