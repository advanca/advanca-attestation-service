###### Defines the list of items to make ######################################
# ATTN: ORDER MATTERS!!!
# Make sure that the appropriate components are built in order.

STUFF_TO_MAKE := isv_enclave isv_app

###### Derive stuff to clean from items to make ###############################

STUFF_TO_CLEAN := $(addsuffix .clean,$(STUFF_TO_MAKE))

###############################################################################


.PHONY: all clean $(STUFF_TO_MAKE) $(STUFF_TO_CLEAN)

target: all

all: $(STUFF_TO_MAKE)

clean: $(STUFF_TO_CLEAN)

$(STUFF_TO_CLEAN):
	$(MAKE) -C  $(basename $@) clean


$(STUFF_TO_MAKE):
	$(MAKE) -C $@
	INSTALL_DIR=${CURDIR} $(MAKE) -C $@ install
