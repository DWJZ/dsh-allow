#!/bin/sh
# Restore this profile composition after the desktop app resets it.
# Usage: sh restore.sh   (from anywhere)
set -e
src=$(cd "$(dirname "$0")" && pwd)
dst="$HOME/.dsh/profiles/desktop"
cp "$src/cordis.patch.yml" "$dst/cordis.patch.yml"
node -e '
const fs=require("fs"), path=require("path");
const src=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
const dstPath=process.argv[2];
const dst=JSON.parse(fs.readFileSync(dstPath,"utf8"));
const want=src.dsh.profile.bundles;
const have=dst.dsh.profile.bundles;
for(const name of want) if(!have.includes(name)) have.push(name);
fs.writeFileSync(dstPath, JSON.stringify(dst,null,2)+"\n");
console.log("bundles:", JSON.stringify(have));
' "$src/package.json" "$dst/package.json"
echo "restored: $dst"
