#!/bin/bash
# Frame CPU times of every view of the GUI, per view and layout.
#
#   scripts/gui-frames.sh FILE [FROM TO [XREFS]]
#
# Opens FILE in the GUI through a guarded driver (X, default: x.sh beside
# this script; what it takes is below), shows each view in turn (listing,
# C, graph, hex, IR, call graph, Pathfinder with a
# path from FROM to TO, strings, the cross-references to XREFS, the struct
# editor), in the default two-pane layout and maximised, scrolls it with
# the wheel and prints the median, 90th percentile and maximum of the
# frames' CPU time (BINBUN_FRAME_TRACE: render to the end of paint) per
# view. FROM, TO and XREFS are names Go Anywhere finds (default: main,
# shell_execve, xmalloc: bash's). The struct editor edits the struct the C
# shows at STRUCT="X Y" (window coordinates, with TO's C on screen) if
# given, else a new struct. SHOTS=1 takes a screenshot of each view
# (shots/frames-<view>-<layout>.png beside the driver).
#
# The driver takes: run FILE, kill, key KEYS..., type TEXT, wheel X Y N
# [up|down], shot NAME; it starts the app with the inherited environment
# and writes its stderr to app.log beside it, the app being binbun (the
# GUI's build) beside it. The positions assume its headless output of 1920x1080 with
# the default layout (map, listing, C). Each view is measured once the app
# is idle (under a tenth of a core for a second): its own background work
# (warming, verifying) would otherwise take the frames' cores.
set -u
here=$(cd "$(dirname "$0")" && pwd)
X=${X:-$here/x.sh}
dir=$(dirname "$X")
LOG=${LOG:-$dir/app.log}
file=${1:?usage: gui-frames.sh FILE [FROM TO [XREFS]]}
from=${2:-main}
to=${3:-shell_execve}
xrefs=${4:-xmalloc}
NOTCHES=${NOTCHES:-10}
export BINBUN_FRAME_TRACE=1

x() { env -u DISPLAY "$X" "$@" >/dev/null || exit 1; }
palette() { x key ctrl+shift+p; sleep 0.4; x type "$1"; sleep 0.4; x key Return; sleep 0.3; x key Escape; sleep 0.6; }
goto() { x key g; sleep 0.4; x type "$1"; sleep 0.8; x key Return; sleep 0.8; }
left() { x key ctrl+k ctrl+Left; sleep 0.3; }
right() { x key ctrl+k ctrl+Right; sleep 0.3; }

# Pane centres (window coordinates): the listing's, the C's, a maximised
# pane's, the right dock's.
L="660 400"
R="1490 600"
M="1100 400"
D="1750 400"

# The frames traced since line $1 of the log: count, median, p90, max.
stats() {
  tail -n +"$(($1 + 1))" "$LOG" | awk '/^frame / {print $2}' | sort -n |
    awk '{a[NR] = $1} END {
      if (NR == 0) { printf "%5d %8s %8s %8s", 0, "-", "-", "-"; exit }
      p = int(NR * 0.9 + 0.5); if (p < 1) p = 1
      printf "%5d %8.2f %8.2f %8.2f", NR, a[int((NR + 1) / 2)], a[p], a[NR]
    }'
}

# Waits (up to two minutes) until the app uses under a tenth of a core
# for a second (/proc's clock ticks, 100 a second).
idle() {
  local pid t0 t1
  pid=$(pgrep -n -f "$dir/binbun") || return 0
  for _ in $(seq 120); do
    t0=$(awk '{print $14 + $15}' "/proc/$pid/stat") || return 0
    sleep 1
    t1=$(awk '{print $14 + $15}' "/proc/$pid/stat") || return 0
    [ $((t1 - t0)) -le 10 ] && return 0
  done
}

# Scrolls at "X Y" down and up again; prints the view's line.
measure() {
  local name=$1 at=$2 layout=$3 start
  idle
  start=$(grep -c . "$LOG")
  # shellcheck disable=SC2086
  x wheel $at "$NOTCHES" down
  if [ -n "${SHOTS:-}" ]; then sleep 0.5; x shot "frames-$name-$layout"; fi
  # shellcheck disable=SC2086
  x wheel $at "$NOTCHES" up
  sleep 1
  printf "%-12s %-8s %s\n" "$name" "$layout" "$(stats "$start")"
}

# The view in both layouts: two panes at "$2", maximised at $M.
both() {
  measure "$1" "$2" panes
  x key shift+Escape
  measure "$1" "$M" max
  x key shift+Escape
  sleep 0.3
}

# The default layout, not the one an earlier run left in the project.
rm -f "$file.binbun.toml.layout.toml"
x run "$file"
sleep 2
printf "%-12s %-8s %5s %8s %8s %8s\n" view layout n median p90 max
left
both listing "$L"
right
both c "$R"
left
x key space
both graph "$L"
x key space
left
palette "Hex View"
both hex "$L"
palette "Hex View"
left
x key ctrl+k i
sleep 1
both ir "$R"
x key ctrl+k i
left
x key ctrl+F12
sleep 1
both calls "$L"
x key ctrl+F12
left
goto "$from"
palette "Path from Here"
goto "$to"
palette "Path to Here"
sleep 2
measure pathfinder "$D" panes
if [ -n "${STRUCT:-}" ]; then
  right
  # shellcheck disable=SC2086
  x click $STRUCT
  palette "Edit Struct"
  sleep 1
  both struct "$R"
  x key ctrl+w
fi
x key ctrl+alt+b
goto "$from"
left
x key shift+F12
sleep 1
both strings "$L"
x key ctrl+w
goto "$xrefs"
x key x
sleep 1
both xrefs "$L"
x key ctrl+w
if [ -z "${STRUCT:-}" ]; then
  palette "New Struct"
  sleep 1
  both struct "$L"
  x key ctrl+w
fi
x kill
