#!/bin/bash
# The preview image of the README and binbun.org, once per theme.
#
#   scripts/preview.sh [GUI]
#
# Opens bash in the GUI (GUI, else $BINBUN_GUI, else the release build in
# gui/target/release/binbun) at get_directory_stack, in the default layout
# (the map, the listing, the function's C beside it), in a private
# headless sway at 1920x1200 and scale 1, and takes the window with grim,
# once per theme: Dark Modern (the default) and One Light. Writes
# site/static/assets/preview/<theme>.webp
# (lossless WebP: smaller than lossy at quality 80 for these images, and
# exact). Run it again at each release.
#
# The binary is Debian 12's bash (5.2.15-2+b7, amd64), the same bytes on
# every machine: the package is fetched once from snapshot.debian.org
# into target/preview and checked against its SHA-256, as is the bash in
# it. The app is steered without input: each run has its own BINBUN_HOME
# with settings that pick the theme and a saved layout (the project's
# layout.toml) that puts the listing and the C at the function. A window
# is taken once the analysis is warmed and the window has drawn no frame
# for two seconds (BINBUN_TRACE and BINBUN_FRAME_TRACE on its stderr).
#
# The sway runs on the headless backend with its own XDG_RUNTIME_DIR and
# no Xwayland; the app talks to it alone (DISPLAY and the caller's
# WAYLAND_DISPLAY are never passed on). Only the processes the script
# started are stopped, by their process ids. Scratch files are in
# target/preview/run.*, removed after a successful run and kept (with the
# logs) after a failed one.
#
# Requires: sway, swaymsg, grim, magick (ImageMagick 7 with WebP), curl,
# ar, tar with xz, sha256sum, jq.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
gui=${1:-${BINBUN_GUI:-$root/gui/target/release/binbun}}
out=$root/site/static/assets/preview
work=$root/target/preview

# The window: its output's size in pixels, at scale 1.
width=1920
height=1200
# The function shown: its C, shown from its first line, nearly fills the
# pane.
function=get_directory_stack

# Debian 12's bash: the package, its SHA-256 and the binary's.
deb_url='https://snapshot.debian.org/archive/debian/20240331T210805Z/pool/main/b/bash/bash_5.2.15-2%2Bb7_amd64.deb'
deb_sha256=d3c65202568384a588ea32017b243fe64ca054943a008cba4e5bd8f9e79975c4
bash_sha256=a4b895f98db75079f2af6e510c95db0d5c5d596e448bf3fe689d0bfdd182e28e

# The themes: the file's name, the window's theme (dark or light) and
# the theme's name.
themes=(
  "one-dark dark One Dark"
  "one-light light One Light"
)

fail() {
  echo "preview.sh: $*" >&2
  exit 1
}

missing=()
for tool in sway swaymsg grim magick curl ar tar xz sha256sum jq; do
  command -v "$tool" >/dev/null || missing+=("$tool")
done
if ((${#missing[@]})); then
  fail "missing ${missing[*]} (needs sway, swaymsg, grim, magick, curl, ar, tar, xz, sha256sum, jq)"
fi
[[ $(magick -list format) =~ WEBP\*?\ +WEBP\ +rw ]] || fail "magick cannot write WebP"
[[ -x $gui ]] || fail "no GUI at $gui (build it: cargo build --release in gui/, or pass its path)"
gui=$(cd "$(dirname "$gui")" && pwd)/$(basename "$gui")

# The binary, fetched once.
mkdir -p "$work"
bin=$work/bash-5.2.15-2+b7/bash
if [[ ! -f $bin ]] || [[ $(sha256sum <"$bin") != "$bash_sha256  -" ]]; then
  deb=$work/bash_5.2.15-2+b7_amd64.deb
  if [[ ! -f $deb ]] || [[ $(sha256sum <"$deb") != "$deb_sha256  -" ]]; then
    echo "fetching $deb_url"
    curl -fsSL --retry 3 -o "$deb.part" "$deb_url" || fail "cannot fetch $deb_url"
    [[ $(sha256sum <"$deb.part") == "$deb_sha256  -" ]] || fail "$deb_url: unexpected SHA-256"
    mv "$deb.part" "$deb"
  fi
  mkdir -p "$(dirname "$bin")"
  ar p "$deb" data.tar.xz | tar -xJO ./bin/bash >"$bin.part"
  [[ $(sha256sum <"$bin.part") == "$bash_sha256  -" ]] || fail "$deb: its bash has an unexpected SHA-256"
  mv "$bin.part" "$bin"
fi

run=$(mktemp -d "$work/run.XXXXXX")
sway_pid=
app_pid=
ok=
# Stops what this script started, and only that.
cleanup() {
  local pid
  for pid in $app_pid $sway_pid; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  if [[ -n $ok ]]; then
    rm -rf "$run"
  else
    echo "preview.sh: logs kept in $run" >&2
  fi
}
trap cleanup EXIT

# Waits up to $1 seconds until the command after $2 (what it waits for)
# succeeds.
wait_for() {
  local deadline=$((SECONDS + $1)) what=$2
  shift 2
  until "$@"; do
    ((SECONDS < deadline)) || fail "waited $what for too long"
    sleep 0.1
  done
}

# The function's entry, as the analysis finds it.
entry=$(env -i PATH="$PATH" HOME="$run/cli" BINBUN_HOME="$run/cli" BINBUN_UPDATE_CHECK=off \
  "$gui" functions "$bin" | awk -v f="$function" '$NF == f { print $1 }')
[[ $entry == 0x* ]] || fail "no function $function in $bin"
entry=0x$(printf '%X' "$entry")

# The headless sway.
xdg=$run/xdg
mkdir -m 700 "$xdg"
cat >"$run/sway.conf" <<EOF
output HEADLESS-1 resolution ${width}x$height scale 1
swaybg_command -
xwayland disable
default_border none
default_floating_border none
gaps inner 0
gaps outer 0
EOF
env -i PATH="$PATH" HOME="$run" XDG_RUNTIME_DIR="$xdg" \
  WLR_BACKENDS=headless WLR_LIBINPUT_NO_DEVICES=1 WLR_RENDERER=pixman \
  sway -c "$run/sway.conf" >"$run/sway.log" 2>&1 &
sway_pid=$!
sway_ready() {
  kill -0 "$sway_pid" 2>/dev/null || fail "sway exited (see $run/sway.log)"
  [[ -S $xdg/sway-ipc.$UID.$sway_pid.sock ]] && [[ -S $xdg/wayland-1 ]]
}
wait_for 30 "for sway" sway_ready
ipc() { swaymsg -s "$xdg/sway-ipc.$UID.$sway_pid.sock" "$@"; }
[[ $(ipc -t get_outputs -r | jq -r '[.[].name] | join(" ")') == HEADLESS-1 ]] ||
  fail "sway has outputs other than HEADLESS-1"

# The app's state, from its log ($log) and process ($app_pid).
alive() { kill -0 "$app_pid" 2>/dev/null || fail "the app exited (see $log)"; }
gone() { ! kill -0 "$app_pid" 2>/dev/null; }
# The analysis warmed and a function's C printed.
analysed() { alive && grep -q 'stage Warmed' "$log" && grep -q '^C request → document' "$log"; }
# No frame drawn for two seconds (since $since, $frames frames before).
settled() {
  alive
  local count now
  count=$(grep -c '^frame ' "$log" || true)
  now=$(date +%s%N)
  if [[ $count != "$frames" ]]; then
    frames=$count
    since=$now
    return 1
  fi
  ((count > 0 && now - since >= 2000000000))
}

key=$(sha256sum <"$bin")
key=${key%% *}
mkdir -p "$out"
for theme in "${themes[@]}"; do
  read -r slug mode name <<<"$theme"
  echo "$slug: $name"
  home=$run/$slug
  mkdir -p "$home/config" "$home/data/projects/$key-bash"
  cat >"$home/config/settings.toml" <<EOF
[window]
theme = "$mode"
${mode}_theme = "$name"

[symbols]
download = "never"

[updates]
check = "never"
EOF
  cat >"$home/data/projects/$key-bash/layout.toml" <<EOF
focused = 0
sidebar = 240.0
tree = { split = "row", sizes = [0.5, 0.5], children = [{ pane = 0 }, { pane = 1 }] }

[[pane]]
id = 0
active = 0
synced = true
tabs = [{ kind = "listing", at = "$entry" }]

[[pane]]
id = 1
active = 0
synced = true
tabs = [{ kind = "c", entry = "$entry", view = "reading", at = "$entry" }]
EOF
  log=$run/$slug.log
  env -i PATH="$PATH" HOME="$home" LANG=C.UTF-8 XDG_RUNTIME_DIR="$xdg" WAYLAND_DISPLAY=wayland-1 \
    BINBUN_HOME="$home" BINBUN_UPDATE_CHECK=off BINBUN_TRACE=1 BINBUN_FRAME_TRACE=1 \
    "$gui" "$bin" >"$log" 2>&1 &
  app_pid=$!
  wait_for 300 "for the analysis" analysed
  frames=-1
  since=0
  wait_for 120 "for the window to settle" settled

  # The window's rectangle on the output.
  rect=$(ipc -t get_tree -r | jq -r --argjson pid "$app_pid" \
    'first(.. | objects | select(.pid? == $pid) | .rect | "\(.x),\(.y) \(.width)x\(.height)")')
  [[ -n $rect ]] || fail "no window of the app's in sway's tree"
  env -i PATH="$PATH" XDG_RUNTIME_DIR="$xdg" WAYLAND_DISPLAY=wayland-1 \
    grim -g "$rect" -t png "$run/$slug.png"

  # Closed as a user would (the layout and project are scratch).
  ipc "[pid=$app_pid] kill" >/dev/null
  wait_for 20 "for the app to quit" gone
  wait "$app_pid" 2>/dev/null || true
  app_pid=

  magick "$run/$slug.png" -strip -define webp:lossless=true -define webp:method=6 -quality 100 \
    "$out/$slug.webp"
  echo "  $out/$slug.webp: $(stat -c %s "$out/$slug.webp") bytes"
done
ok=1
