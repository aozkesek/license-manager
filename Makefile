SUBDIRS := liblicense license_provider license_customer

.PHONY: all cleanall $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -w -C $@
				
cleanall: 
	$(foreach subdir,$(SUBDIRS), make -w -C $(subdir) clean;)