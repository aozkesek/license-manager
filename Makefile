include make.inc

SUBDIRS := liblicense license_customer license_provider


.PHONY: all cleanall $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -w -C $@
				
cleanall: 
	$(foreach subdir,$(SUBDIRS), make -w -C $(subdir) clean;)
