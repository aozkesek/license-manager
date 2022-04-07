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
	@rm tmp-* -f
	@echo
	@license_customer/license_customer
	@echo
	@license_provider/license_provider
	@echo
	@license_customer/license_customer testee tester 1.0 testsvc:1.0
	@echo
	@cat tmp-customer.lic
	@echo
	@license_provider/license_provider 3650
	@echo
	@license_provider/license_provider 36
	@echo
	@license_provider/license_provider demo
	
