#!/bin/bash
set -eu

version=$(git tag -l | sort --version-sort -r | head -1 | sed 's/^v//')
if [ -z "$version" ]; then
	version="0.0.0"
fi
 
a=( ${version//./ } )
((a[2]++))
echo "${a[0]}.${a[1]}.${a[2]}"       
