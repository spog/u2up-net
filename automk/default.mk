#
# The "automk" project build rules
#
# Copyright (C) 2017-2018 Samo Pogacnik <samo_pogacnik@t-2.net>
# All rights reserved.
#
# This file is part of the "automk" software project.
# This file is provided under the terms of the BSD 3-Clause license,
# available in the LICENSE file of the "automk" software project.
#

SHELL := /bin/bash
MAKEFILE := auto.mk
CONFIG_MKFILE := config.mk
_OBJDIR_ := $(_BUILDIR_)/$(SUBPATH)
_INSTALL_PREFIX_ := $(DESTDIR)$(PREFIX)
export SHELL MAKEFILE CONFIG_MKFILE
export _OBJDIR_ _INSTALL_PREFIX_

include $(CONFIG_MKFILE)
TARGETS = all install clean

.PHONY: $(TARGETS)
$(TARGETS):
	$(_SRCDIR_)/automk/default.sh targets_make $@

.PHONY: env
env: all
	env

