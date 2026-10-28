#!/usr/bin/env bash
# Builds a Windows release and packs it with the matching SoftEther drivers:
#   dist/EasyEther-<version>-windows-<arch>.zip
#     EasyEther/easyether.exe
#     EasyEther/LICENSE, NOTICE, README.md
#     EasyEther/drivers/install-drivers.bat, uninstall-drivers.bat
#     EasyEther/drivers/{selow,neo}/...  + LICENSE-SoftEther.txt
#
# Usage: ./package-windows.sh [x64|x86] [path/to/easyether.exe]
#   Default arch: x64. Without an exe path it cross-compiles with the matching
#   *-pc-windows-gnu target (rustup target add ...; needs mingw-w64-gcc).
set -euo pipefail
cd "$(dirname "$0")"

arch=${1:-x64}
case $arch in
    x64) target=x86_64-pc-windows-gnu ;;
    x86) target=i686-pc-windows-gnu ;;
    *) echo "arch must be x64 or x86" >&2; exit 2 ;;
esac
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

if [[ $# -ge 2 ]]; then
    exe=$2
else
    cargo build --release --target "$target"
    exe=target/$target/release/easyether.exe
fi

drivers=(selow/SeLow_$arch.sys selow/SeLow_$arch.inf selow/SeLow_Win10_$arch.cat
         neo/Neo6_${arch}_VPN127.sys neo/Neo6_${arch}_VPN127.inf neo/Neo6_${arch}_VPN127.cat)
for f in "${drivers[@]}"; do
    [[ -f drivers/$f ]] || { echo "missing drivers/$f" >&2; exit 1; }
done

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/EasyEther/drivers/selow" "$stage/EasyEther/drivers/neo"
cp "$exe" "$stage/EasyEther/easyether.exe"
for f in "${drivers[@]}"; do
    cp "drivers/$f" "$stage/EasyEther/drivers/$f"
done
cp drivers/LICENSE-SoftEther.txt "$stage/EasyEther/drivers/"
cp LICENSE NOTICE README.md "$stage/EasyEther/"
# Windows line endings for the batch files.
for bat in windows/*.bat; do
    sed 's/$/\r/' "$bat" > "$stage/EasyEther/drivers/$(basename "$bat")"
done

mkdir -p dist
out="$PWD/dist/EasyEther-$version-windows-$arch.zip"
rm -f "$out"
(cd "$stage" && zip -qr "$out" EasyEther)
echo "Created $out"
