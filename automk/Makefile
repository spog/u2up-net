MAKE := $(shell which make)
export MAKE

_SRCDIR_ := $(PWD)
_BUILDIR_ := $(_SRCDIR_)/.build
SUBPATH := .
export _SRCDIR_ _BUILDIR_ SUBPATH

include $(_BUILDIR_)/auto.mk

