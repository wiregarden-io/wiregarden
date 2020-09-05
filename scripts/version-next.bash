#!/bin/bash
set -eu

version=$(git tag -l | sort --version-sort -r | head -1 | sed 's/^v//')                                                                                                                                       
a=( ${version//./ } )
((a[2]++))
echo "${a[0]}.${a[1]}.${a[2]}"       
