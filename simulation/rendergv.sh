#!/bin/sh

$(head ${1} -n1 | sed -e 's%\/\* %%' | sed -e 's% \*\/%%')
