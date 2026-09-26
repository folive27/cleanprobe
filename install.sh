#!/usr/bin/env bash
# cleanprobe easy installer
#
# One-line install:
#   curl -fsSL https://raw.githubusercontent.com/folive27/cleanprobe/main/install.sh | bash
#
# Or from a checkout:
#   ./install.sh
#
# Options (environment variables):
#   CLEANPROBE_HOME            install directory        (default: ~/.cleanprobe)
#   CLEANPROBE_BIN             where the command goes   (default: ~/.local/bin)
#   CLEANPROBE_FORCE_TARBALL=1 skip git, download a tarball instead
#
# Needs: python3 (3.9+), and either git or curl+tar. No root required.
set -euo pipefail

REPO="folive27/cleanprobe"
REPO_URL="https://github.com/${REPO}.git"
TARBALL="https://codeload.github.com/${REPO}/tar.gz/refs/heads/main"

HOME_DIR="${CLEANPROBE_HOME:-$HOME/.cleanprobe}"
BIN_DIR="${CLEANPROBE_BIN:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }

# --- 1. find a suitable python -------------------------------------------------
PY=""
for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1; then
        if "$c" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
            PY="$c"; break
        fi
    fi
done
if [ -z "$PY" ]; then
    say "ERROR: Python 3.9 or newer is required, and was not found."
    say "Install it first, then run this again."
    say "  Debian/Ubuntu:  sudo apt install python3 python3-venv"
    exit 1
fi
say "==> python: $("$PY" --version 2>&1)"

# --- 2. get the source ----------------------------------------------------------
SRC=""
if [ -f "pyproject.toml" ] && grep -q '^name = "cleanprobe"' pyproject.toml 2>/dev/null; then
    SRC="$PWD"
    say "==> using this checkout: $SRC"
else
    mkdir -p "$HOME_DIR"
    if [ -d "$HOME_DIR/src/.git" ] && [ -z "${CLEANPROBE_FORCE_TARBALL:-}" ]; then
        say "==> updating existing download..."
        git -C "$HOME_DIR/src" pull --ff-only --quiet || say "(update skipped)"
    elif command -v git >/dev/null 2>&1 && [ -z "${CLEANPROBE_FORCE_TARBALL:-}" ]; then
        say "==> downloading (git)..."
        rm -rf "$HOME_DIR/src"
        git clone --quiet --depth 1 "$REPO_URL" "$HOME_DIR/src"
    elif command -v curl >/dev/null 2>&1 && command -v tar >/dev/null 2>&1; then
        say "==> downloading (tarball)..."
        rm -rf "$HOME_DIR/src"
        mkdir -p "$HOME_DIR/src"
        curl -fsSL "$TARBALL" | tar xz -C "$HOME_DIR/src" --strip-components=1
    else
        say "ERROR: need git or curl+tar to download the source. Install one and retry."
        exit 1
    fi
    SRC="$HOME_DIR/src"
fi

# --- 3. install ------------------------------------------------------------------
VENV="$HOME_DIR/venv"
if [ ! -x "$VENV/bin/python" ]; then
    say "==> creating virtual environment..."
    if ! "$PY" -m venv "$VENV" 2>/dev/null; then
        say "ERROR: could not create a virtual environment."
        say "On Debian/Ubuntu run:  sudo apt install python3 python3-venv"
        exit 1
    fi
fi
say "==> installing (the first run can take a minute)..."
"$VENV/bin/pip" install --quiet --upgrade pip >/dev/null 2>&1 || true
if ! "$VENV/bin/pip" install --quiet -e "$SRC"; then
    say "ERROR: install failed. Check your internet connection and retry."
    exit 1
fi

# --- 4. launcher ------------------------------------------------------------------
mkdir -p "$BIN_DIR"
cat > "$BIN_DIR/cleanprobe" <<LAUNCHER
#!/usr/bin/env bash
exec "$VENV/bin/cleanprobe" "\$@"
LAUNCHER
chmod +x "$BIN_DIR/cleanprobe"

say ""
say "done. installed as: $BIN_DIR/cleanprobe"
say ""
say "quick test:"
say "  \"$BIN_DIR/cleanprobe\" selftest"
case ":$PATH:" in
    *":$BIN_DIR:"*)
        say ""
        say "then just run:  cleanprobe --help" ;;
    *)
        say ""
        say "one more step - make the command available in your shell:"
        say "  echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.bashrc && exec bash"
        say "(or run it with the full path shown above)" ;;
esac
