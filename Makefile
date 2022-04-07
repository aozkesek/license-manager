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
	@clear
	@echo "testing the customer and provider apps..."
	@rm tmp-*.pem

	@license_customer/license_customer genkey
	@license_provider/license_provider genkey

	@license_customer/license_customer test
	@license_provider/license_provider test
