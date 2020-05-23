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
SUBMAKES :=
CONFIG_MKFILE := config.mk
export SHELL MAKEFILE SUBMAKES CONFIG_MKFILE

SUBPATH := $(shell $(_SRCDIR_)/automk/default.sh subpath_set)

include $(CONFIG_MKFILE)

.PHONY: configure
configure: $(_SRCDIR_)/.build/$(SUBPATH)/$(MAKEFILE)
	$(_SRCDIR_)/automk/default.sh submakes_config $(SUBPATH)

$(_SRCDIR_)/.build/$(SUBPATH)/$(MAKEFILE): $(CONFIG_MKFILE)
	$(_SRCDIR_)/automk/default.sh generate_makefile $(SUBPATH)


