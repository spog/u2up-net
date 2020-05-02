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

SUBMAKES := simulation
export SUBMAKES

comp_version_MAJOR := 0
comp_version_MINOR := 1
comp_version_PATCH := 0
export  comp_version_MAJOR comp_version_MINOR comp_version_PATCH

CFLAGS := -g -Wall -I$(_SRCDIR_)/include -DEVM_VERSION_MAJOR=$(comp_version_MAJOR) -DEVM_VERSION_MINOR=$(comp_version_MINOR) -DEVM_VERSION_PATCH=$(comp_version_PATCH) -DU2UP_LOG_MODULE_DEBUG=1 -DU2UP_LOG_MODULE_TRACE=1
LDFLAGS := -L$(_BUILDIR_)/libs/evm
export CFLAGS LDFLAGS

