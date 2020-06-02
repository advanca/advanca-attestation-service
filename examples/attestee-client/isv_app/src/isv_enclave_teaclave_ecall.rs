// Copyright (C) 2020 ADVANCA PTE. LTD.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use sgx_types::*;
use advanca_crypto_ctypes::*;
extern "C" {
    pub fn init (eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
    pub fn enclave_init_ra (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, b_pse: i32, p_context: *mut sgx_ra_context_t) -> sgx_status_t;
    pub fn enclave_ra_close (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, context: sgx_ra_context_t) -> sgx_status_t;
    pub fn print_keys (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, context: sgx_ra_context_t) -> sgx_status_t;
    pub fn gen_ec256_pubkey (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, context: sgx_ra_context_t, aas_request: *mut CAasRegRequest) -> sgx_status_t;
    pub fn compute_ec256_shared_dhkey (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, context: sgx_ra_context_t, ephemeral_key: *const CSgxEphemeralKey) -> sgx_status_t;
}
