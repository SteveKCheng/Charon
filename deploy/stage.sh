#!/bin/sh
set -eu

script_dir="$(dirname -- "$0")"
top_dir="$script_dir/.."

usage()
{
    cat << EOF
Usage: $0 OUT-DIR

This script stages files from Charon's published build for running as a
background service.  It works with development versions of Charon.

OUT-DIR is the top-level directory where Charon's files will be copied into.
The directory tree is laid out as follows:

  - Each version of Charon, as computed by GitVersion.MsBuild, will get its 
    own sub-directory under OUT-DIR.
  - If that sub-directory already exists, it will be removed beforehand.
  - A symbolic link named "latest", under OUT-DIR, will be established to
    point to the sub-directory for the version of Charon staged by the
    run of this script.

This script is intended to support swapping out Charon's files while an 
instance is already running (as a background service):

  - To make that work, Charon should be started in a mount (filesystem) 
    namespace where the sub-directory that "latest" points to is 
    bind-mounted as a new directory.  
  - Call this bind-mounted directory "current".
  - Start Charon from the directory "current".
  - Bind-mounting makes all paths under "current" always refer to the
    same directory inode, for the lifetime of the Charon process.
  - Updates to files for a new version will not disturb an existing
    process, even though the updates necessarily cannot be atomic, because
    there are multiple files.
  - When restarting Charon, refresh the bind-mount "current" to the 
    subdirectory of the new version.

EOF
}

if [ $# -ne 1 ] || [ -z "$1" ] ; then
    echo >&2 "$0: incorrect arguments"
    usage
    exit 1
fi

version="$(dotnet msbuild "$top_dir/src/Charon/Charon.csproj" -t:GetVersion -getProperty:Version)"
out_dir="$1"

mkdir -p "$out_dir/current"

rm -rf "$out_dir/$version"

cp -a "$top_dir/out/publish/Charon/release_linux-x64" "$out_dir/$version"
ln -snf "$version" "$out_dir/latest"

