include common.mk

SUBDIRS := liblicense license_customer license_provider

.PHONY: all $(SUBDIRS)

# target: prerequsites
#    recipe

all : $(SUBDIRS)

$(SUBDIRS) :
	$(MAKE) -w -C $@

clean :
	$(foreach subdir, $(SUBDIRS), make -w -C $(subdir) clean;)

test :
	rm tmp-*.pem
	license_provider/license_provider test
