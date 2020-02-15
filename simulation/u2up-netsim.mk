#
# The "u2up-net" project build rules
#
# This file is part of the "u2up-net" software project.
#
#  Copyright (C) 2020 Samo Pogacnik <samo_pogacnik@t-2.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

TARGET := u2up-netsim
_INSTDIR_ := $(_INSTALL_PREFIX_)/bin

# Files to be compiled:
SRCS := u2up-net-common.c $(TARGET).c

# include automatic _OBJS_ compilation and SRCSx dependencies generation
include $(_SRCDIR_)/automk/objs.mk

.PHONY: all
all: $(_OBJDIR_)/$(TARGET)

$(_OBJDIR_)/$(TARGET): $(_OBJS_)
	$(CC) $(_OBJS_) -o $@ $(LDFLAGS) -levm -lrt -lpthread -Wl,-rpath=../lib

.PHONY: clean
clean:
	rm -f $(_OBJDIR_)/$(TARGET) $(_OBJDIR_)/$(TARGET).o $(_OBJDIR_)/$(TARGET).d $(_OBJDIR_)/u2up-net-common.o $(_OBJDIR_)/u2up-net-common.d

.PHONY: install
install: $(_INSTDIR_) $(_INSTDIR_)/$(TARGET)

$(_INSTDIR_):
	install -d $@

$(_INSTDIR_)/$(TARGET): $(_OBJDIR_)/$(TARGET)
	install $(_OBJDIR_)/$(TARGET) $@

