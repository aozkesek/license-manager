SUBDIRS := liblicense license_private license_public

.PHONY: all cleanall $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -w -C $@
				
cleanall: 
	$(foreach subdir,$(SUBDIRS), make -w -C $(subdir) clean;)