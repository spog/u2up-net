#!/bin/sh

while [ -n "$1" ]; do
	echo $1
	$(head ${1} -n1 | sed -e 's%\/\* %%' | sed -e 's% \*\/%%')
	shift
done

