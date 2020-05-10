include ../buildenv.mk

# Enclave Specific Setting #####################################################
#
ENCLAVE_NAME := isv_enclave
ENCLAVE_SIGNING_KEY := isv_enclave_signkey_private.pem
ENCLAVE_CONFIG := isv_enclave.config.xml
ENCLAVE_VS := isv_enclave.lds
ENCLAVE_EDL := isv_enclave.edl

USE_PREFIX := 


# Derived values from the settings.
ENCLAVE_COMPILED := lib$(ENCLAVE_NAME).a
ENCLAVE := $(ENCLAVE_NAME).so
SIGNED_ENCLAVE := $(ENCLAVE_NAME).signed.so

BASE_EDL_NAME := $(basename $(ENCLAVE_EDL))
TRUSTED_EDL := $(BASE_EDL_NAME)_t
UNTRUSTED_EDL := $(BASE_EDL_NAME)_u

################################################################################

Crypto_Library_Name := sgx_tcrypto

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

# Enable the security flags
Enclave_Security_Link_Flags := -Wl,-z,relro,-z,now,-z,noexecstack

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
ENCLAVE_LINK_FLAGS := $(Enclave_Security_Link_Flags) \
                      -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
                      -Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
                      -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) \
                                        -lsgx_ukey_exchange -lsgx_tkey_exchange \
                                        -lcompiler-rt-patch -l$(ENCLAVE_NAME) \
                      -Wl,--end-group \
                      -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
                      -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
                      -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
                      -Wl,--version-script=$(ENCLAVE_VS)

SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wconversion -Wredundant-decls

SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) \
                     -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants

Enclave_Include_Paths := -I$(SGX_SDK)/include \
                         -I$(SGX_SDK)/include/libcxx \
			 -I$(RUST_SGX_COMMON_INC) \
			 -I$(RUST_SGX_EDL_INC) \

Enclave_C_Flags := $(Enclave_Include_Paths) \
                   -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections

CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
	Enclave_C_Flags += -fstack-protector
else
	Enclave_C_Flags += -fstack-protector-strong
endif
Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++

ifeq ($(LAv2), 1)
	Enclave_C_Flags += -DSGX_USE_LAv2_INITIATOR
	Enclave_Cpp_Flags += -DSGX_USE_LAv2_INITIATOR
endif

.PHONY:  all clean target prep install check_env interface

target: prep build/$(SIGNED_ENCLAVE) build/lib$(UNTRUSTED_EDL).a

all: prep target

clean:
	@rm -rf build/ target/

install: guard-INSTALL_DIR
	cp build/lib$(UNTRUSTED_EDL).a $(INSTALL_DIR)/libs/
	cp build/$(SIGNED_ENCLAVE) $(INSTALL_DIR)/bin/

######## Generate the rust extern interfaces ##################################
interface: 
	@sgx_edger8r --use-prefix $(ENCLAVE_EDL) --search-path $(SGX_SDK)/include --search-path $(RUST_SGX_EDL_INC) --teaclave-dir extern_interface --teaclave


######## Prepare the build environment ########################################

prep: 
	mkdir -p build/temp
	mkdir -p build/edl_interface

######## Dependencies preparation #############################################

build/temp/libcompiler-rt-patch.a:
	cp $(RUST_SGX_SDK_PATH)/compiler-rt/libcompiler-rt-patch.a $@

build/temp/libsgx_ustdc.a:
	cp $(RUST_SGX_SDK_PATH)/sgx_ustdc/libsgx_ustdc.a $@

######## Sign enclave #########################################################

build/$(SIGNED_ENCLAVE): build/$(ENCLAVE)
	@$(SGX_ENCLAVE_SIGNER) sign -key $(ENCLAVE_SIGNING_KEY) -enclave build/$(ENCLAVE) -out $@ -config $(ENCLAVE_CONFIG)
	@echo "SIGN => $@"


######## Build trusted interface ##############################################

build/edl_interface/$(TRUSTED_EDL).o: build/edl_interface/$(TRUSTED_EDL).c
	$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

build/edl_interface/$(TRUSTED_EDL).c: build/edl_interface/$(TRUSTED_EDL).h

build/edl_interface/$(TRUSTED_EDL).h: $(SGX_EDGER8R) $(ENCLAVE_EDL)
	$(SGX_EDGER8R) $(USE_PREFIX) --trusted $(ENCLAVE_EDL) --search-path $(SGX_SDK)/include --search-path $(RUST_SGX_EDL_INC) --trusted-dir build/edl_interface/
	@echo "GEN  =>  $@"

######## Build untrusted interface ############################################

build/lib$(UNTRUSTED_EDL).a: build/edl_interface/$(UNTRUSTED_EDL).o 
	$(AR) rcsD $@ $<

build/edl_interface/$(UNTRUSTED_EDL).o: build/edl_interface/$(UNTRUSTED_EDL).c build/temp/libsgx_ustdc.a
	$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@ 
	@echo "CC   <=  $<"

build/edl_interface/$(UNTRUSTED_EDL).c: build/edl_interface/$(UNTRUSTED_EDL).h

build/edl_interface/$(UNTRUSTED_EDL).h: $(SGX_EDGER8R) $(ENCLAVE_EDL)
	@$(SGX_EDGER8R) $(USE_PREFIX) --untrusted $(ENCLAVE_EDL) --search-path $(SGX_SDK)/include --search-path $(RUST_SGX_EDL_INC) --untrusted-dir build/edl_interface/
	@echo "GEN  =>  $@"

######## Build enclave ########################################################

build/temp/$(ENCLAVE_COMPILED):
	cargo build --release
	cp ./target/release/$(ENCLAVE_COMPILED) $@

build/$(ENCLAVE): ./build/edl_interface/$(TRUSTED_EDL).o ./build/temp/libcompiler-rt-patch.a ./build/temp/$(ENCLAVE_COMPILED)
	$(CXX) -o $@ ./build/edl_interface/$(TRUSTED_EDL).o -lcompiler-rt-patch -l$(ENCLAVE_NAME) $(ENCLAVE_LINK_FLAGS) -L./build/temp/


