#!/bin/sh
#
# submit.sh
#
# Script to help students submitting their assignment:
#  check repo is up-to-date + add proper tag and push to remote
#
# (c) Jean-Cédric Chappelier 02/19
#
prog="$(basename "$0")"
temp="$(mktemp "$prog"-XXXX)"

trap 'err=$?;/bin/rm -f "${temp}" >/dev/null 2>&1; exit $err' 0 1 2 3 15

# ======================================================================
usage () {
    echo "usage: ${prog} [-h|-?] 1|2"
}

# ======================================================================
error () {
    code=$1; shift
    echo "Error: $*" 1>&2
    exit $code
}

# ======================================================================
help () {
    usage
    cat<<EOF

  -h or -? : Print this message and stops.

You shall provide submission number: either 1 (first assignement)
  or 2 (second assignment; no need to use this script for final).

Example:
$0 1
EOF
    exit 0
}

# ======================================================================
proceed() {
    # check we're up to date
    if output="$(git status -suno)"; then
        if [ -n "$output" ]; then
            echo "You have uncommited modifications:"
            echo "$output"
            echo "Please commit or stash before proceeding further"
            return 1
        fi
    else
        error 2 "cannot get current git status"
    fi
    
    # choose proper unused tag
    try=1
    tag="projet0$1_$try"
    git tag -l > "$temp"
    while grep -q "^$tag\$" "$temp"; do
        try=$(($try + 1))
        tag="projet0$1_$try"
    done

    # tags
    git tag "$tag" || error 3 "cannot tag with tag \"$tag\""
    git push --tags || error 4 "cannot push tags to remote"
    git push || error 5 "cannot push to remote"

    echo "Good! Assignement #$1 submitted with tag \"$tag\""
}

# ======================================================================
case "$1" in
    -h|-\?) help;;
esac

proceed "$1"
