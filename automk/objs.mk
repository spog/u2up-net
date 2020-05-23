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

ifneq ($(_OBJDIR_),)

_OBJS_ := $(SRCS:%.c=$(_OBJDIR_)/%.o)

# pull in dependency info for *existing* .o files
-include $(_OBJS_:.o=.d)

$(_OBJDIR_)/%.d:

# compile with dependency info
$(_OBJDIR_)/%.o:
	$(CC) -MM $(CFLAGS) $*.c > $(_OBJDIR_)/$*.d
	@sed -i 's|^.*:|$(_OBJDIR_)\/&|' $(_OBJDIR_)/$*.d
	$(CC) -c $(CFLAGS) $*.c -o $(_OBJDIR_)/$*.o

endif
