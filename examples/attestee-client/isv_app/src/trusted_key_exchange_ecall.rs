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
extern "C" {
    pub fn sgx_ra_proc_msg2_trusted (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, context: sgx_ra_context_t, p_msg2: *const sgx_ra_msg2_t, p_qe_target: *const sgx_target_info_t, p_report: *mut sgx_report_t, nonce: *mut sgx_quote_nonce_t) -> sgx_status_t;
    pub fn sgx_ra_get_msg3_trusted (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, context: sgx_ra_context_t, quote_size: uint32_t, qe_report: *mut sgx_report_t, p_msg3: *mut sgx_ra_msg3_t, msg3_size: uint32_t) -> sgx_status_t;
}
