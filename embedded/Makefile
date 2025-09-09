
...
ifeq ($(MEM_HOOK_ENABLE), 1)
C_FLAGS += -DCARDV_MEM_HOOK_ENABLE=1
WRAP_FLAGS_CARDV := -Wl,--wrap=malloc -Wl,--wrap=free -Wl,--wrap=realloc -Wl,--wrap=calloc
endif
...
install:
	@mkdir -p ${INSTALLDIR}
ifeq ($(MEM_HOOK_ENABLE), 1)
	cp -vf ${BINDIR}/cardv ${INSTALLDIR}/cardv.sym
endif
	@$(STRIP) --strip-unneeded ${BINDIR}/cardv
	rm -rf ${INSTALLDIR}/cardv
	cp -vf ${BINDIR}/cardv ${INSTALLDIR}
	cp -vf ini/default.ini ${INSTALLDIR}

$(OBJPROG):	 $(addprefix $(OBJDIR)/, $(CPP_OBJECTS))
	@mkdir -p $(OMX_TOP)/bin
	@echo "  BIN   $@"
ifeq ($(MEM_HOOK_ENABLE), 1)
	@$(CXX) -o $@  $(addprefix $(OBJDIR)/, $(CPP_OBJECTS)) $(LDFLAGS) $(WRAP_FLAGS_CARDV)
else
	@$(CXX) -o $@  $(addprefix $(OBJDIR)/, $(CPP_OBJECTS)) $(LDFLAGS)
endif
	@echo ""
	@rm -rf ${BINDIR}
	@mkdir ${BINDIR}
	@cp -f ${OBJDIR}/$(PROGS) ${BINDIR}

DFILES := $(foreach dir,$(OBJDIR),$(wildcard $(dir)/*.d))
