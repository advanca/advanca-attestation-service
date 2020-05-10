use sgx_types::*;
extern "C" {
    pub fn init (eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
    pub fn enclave_init_ra (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, b_pse: i32, p_context: *mut sgx_ra_context_t) -> sgx_status_t;
    pub fn enclave_ra_close (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, context: sgx_ra_context_t) -> sgx_status_t;
    pub fn print_keys (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, context: sgx_ra_context_t) -> sgx_status_t;
    pub fn gen_ec256_pubkey (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, context: sgx_ra_context_t, ephemeral_pubkey: *mut sgx_ec256_public_t) -> sgx_status_t;
    pub fn compute_ec256_shared_dhkey (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, context: sgx_ra_context_t, ephemeral_key: *const SgxEphemeralKey) -> sgx_status_t;
}