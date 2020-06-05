
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

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use core::mem::size_of;

use std::collections::HashMap;
use std::boxed::Box;

use sgx_types::*;
use sgx_tkey_exchange::*;

use sgx_types::sgx_ra_key_type_t::*;

use advanca_crypto_ctypes::{CSgxEphemeralKey, CAasRegRequest};
use advanca_crypto::sgx_enclave;
use advanca_crypto::sgx_enclave::sgx_enclave_utils as enclave_utils;

const G_SP_PUB_KEY : sgx_ec256_public_t = sgx_ec256_public_t {
gx: [
        0xe3,0x53,0x79,0x5f,0x40,0x5b,0x8a,0x8f,0x34,0x5c,0xd6,0xbc,0x89,0x1c,0x49,0x6e,
        0x9e,0x56,0x8e,0xcb,0x74,0xee,0x43,0xc1,0x7d,0xed,0xbd,0x04,0x0d,0xea,0x4f,0x1a,
    ],
gy: [
        0x9c,0x98,0x68,0x5c,0xbb,0xb4,0x9b,0x67,0xdd,0x8d,0xd2,0xb6,0x2a,0xb0,0xee,0x09,
        0x3e,0xcc,0x9c,0x39,0x1d,0xa9,0xc9,0xce,0x45,0xf0,0xcf,0xbc,0x0c,0x0f,0x7d,0x89,
    ],
};

#[derive(Default)]
struct SessionInfo {
    user_pubkey      : sgx_ec256_public_t,
    enclave_e_prvkey : sgx_ec256_private_t,
    shared_dhkey     : sgx_ec256_dh_shared_t,
    kdk              : sgx_key_128bit_t,
}

static mut SESSIONS: *mut HashMap<sgx_ra_context_t, SessionInfo> = 0 as *mut HashMap<sgx_ra_context_t, SessionInfo>;

#[no_mangle]
pub extern "C" fn init() -> sgx_status_t {
    let heap_hashmap = Box::new(HashMap::<sgx_ra_context_t, SessionInfo>::new());
    unsafe { SESSIONS = Box::into_raw(heap_hashmap) };
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn enclave_init_ra (b_pse: i32,
                                   p_context: &mut sgx_ra_context_t) -> sgx_status_t {

    let ret: sgx_status_t;
    match rsgx_ra_init(&G_SP_PUB_KEY, b_pse) {
        Ok(p) => {
            *p_context = p;
            ret = sgx_status_t::SGX_SUCCESS;
        },
        Err(x) => {
            ret = x;
            return ret;
        }
    }
    unsafe {(*SESSIONS).insert(*p_context, SessionInfo::default())};
    ret
}

#[no_mangle]
pub extern "C" fn enclave_ra_close (context: sgx_ra_context_t) -> sgx_status_t {
    match rsgx_ra_close(context) {
        Ok(()) => {
            unsafe { (*SESSIONS).remove(&context).unwrap() };
            sgx_status_t::SGX_SUCCESS
        },
        Err(x) => x
    }
}

#[no_mangle]
pub extern "C" fn print_keys (context: sgx_ra_context_t) -> sgx_status_t {
    let mut sk_key = sgx_ra_key_128_t::default();
    let mut mk_key = sgx_ra_key_128_t::default();
    let _ = unsafe {sgx_ra_get_keys(context, SGX_RA_KEY_SK, &mut sk_key)};
    let _ = unsafe {sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mut mk_key)};
    println!("sk: {:02x?}", sk_key);
    println!("mk: {:02x?}", mk_key);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn gen_ec256_pubkey (
        context: sgx_ra_context_t,
        aas_reg_request: &mut CAasRegRequest,
    ) -> sgx_status_t {
    let session_info = unsafe { (*SESSIONS).get_mut(&context).unwrap() };

    let mut p_ecc_handle:sgx_ecc_state_handle_t = 0 as sgx_ecc_state_handle_t;
    let p_private = &mut session_info.enclave_e_prvkey;
    let p_public = &mut sgx_ec256_public_t::default();

    let _ = unsafe {sgx_ecc256_open_context(&mut p_ecc_handle)};
    let _ = unsafe {sgx_ecc256_create_key_pair(p_private, p_public, p_ecc_handle)};
    let _ = unsafe {sgx_ecc256_close_context(p_ecc_handle)};

    let p_public_ptr = p_public as *const sgx_ec256_public_t;
    let data_slice = unsafe{core::slice::from_raw_parts(p_public_ptr as *const u8, size_of::<sgx_ec256_public_t>())};

    let mut mac = sgx_cmac_128bit_tag_t::default();
    enclave_utils::aes128_cmac_sk(context, &data_slice, &mut mac);

    aas_reg_request.pubkey = *p_public;
    aas_reg_request.mac = mac;

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn compute_ec256_shared_dhkey (
        context: sgx_ra_context_t, 
        user_ephemeral: &CSgxEphemeralKey,
    ) -> sgx_status_t {

    let session_info = unsafe { (*SESSIONS).get_mut(&context).unwrap() };

    if !sgx_enclave::ephemeral_key::verify(user_ephemeral, &session_info.user_pubkey) {
        panic!("Key verification failed! PANIC!");
    }

    let mut g_a_pub = user_ephemeral.pubkey;
    let mut g_b_prv = session_info.enclave_e_prvkey;
    let mut gab_x = sgx_ec256_dh_shared_t::default();

    let mut p_ecc_handle:sgx_ecc_state_handle_t = 0 as sgx_ecc_state_handle_t;

    let _ = unsafe {sgx_ecc256_open_context(&mut p_ecc_handle)};
    let _ = unsafe {sgx_ecc256_compute_shared_dhkey(&mut g_b_prv, &mut g_a_pub, &mut gab_x, p_ecc_handle)};
    let _ = unsafe {sgx_ecc256_close_context(p_ecc_handle)};

    session_info.shared_dhkey = gab_x;

    // derive the kdk from the shared dhkey
    // KDK = AES-CMAC(key0, gab x-coordinate)
    let key0 = sgx_cmac_128bit_key_t::default();
    let p_src = &gab_x as *const sgx_ec256_dh_shared_t as *const u8;
    let src_len = size_of::<sgx_ec256_dh_shared_t>() as u32;
    let mut mac = sgx_cmac_128bit_key_t::default();
    let _ = unsafe {sgx_rijndael128_cmac_msg(&key0, p_src, src_len, &mut mac)};

    session_info.kdk = mac;

    sgx_status_t::SGX_SUCCESS
}

