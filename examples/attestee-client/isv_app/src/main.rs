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
use sgx_urts::*;

use std::mem::{size_of};

mod isv_enclave_teaclave_ecall;
use isv_enclave_teaclave_ecall::*;

mod trusted_key_exchange_ecall;
use trusted_key_exchange_ecall::*;

use std::sync::Arc;
use grpcio::*;
use aas_protos::aas::Msg;
use aas_protos::aas::Msg_MsgType as MsgType;
use aas_protos::aas_grpc::AasServerClient;

use futures::{Sink, Stream};

use advanca_crypto_ctypes::CAasRegRequest;
use advanca_crypto_types::*;
use advanca_crypto::*;

fn init_enclave(enclave_name: &str) -> SgxEnclave {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;

    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t { secs_attr: sgx_attributes_t { flags:0, xfrm:0 }, misc_select:0 };
    let result = SgxEnclave::create(enclave_name,
                                    debug,
                                    &mut launch_token,
                                    &mut launch_token_updated,
                                    &mut misc_attr).expect("Error loading enclave!");
    result
}

fn print_sgx_ec256_public_t (key: sgx_ec256_public_t) {
    println!("gx: {:02x?}", key.gx);
    println!("gy: {:02x?}", key.gy);
}

fn main() {
    let isv_enclave = init_enclave("isv_enclave.signed.so");
    let eid = isv_enclave.geteid();

    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut ra_context: sgx_ra_context_t = 10;

    let sgx_return = unsafe {init(eid, &mut retval)};
    println!("sgx_return: {}", sgx_return);
    println!("ra_context: {}", ra_context);

    let sgx_return = unsafe {enclave_init_ra(eid, &mut retval, 0, &mut ra_context)};
    println!("sgx_return: {}", sgx_return);
    println!("ra_context: {}", ra_context);


    // We'll try to connect to the service provider
    let env = Arc::new(Environment::new(2));
    let channel = ChannelBuilder::new(env).connect("127.0.0.1:12345");
    let client = AasServerClient::new(channel);
    let (tx,rx) = client.remote_attest().unwrap();
    // convert to blocking communication
    let mut tx = tx.wait();
    let mut rx = rx.wait();

    let mut extended_epid_gid: u32 = 10;
    let sgx_return = unsafe { sgx_get_extended_epid_group_id(&mut extended_epid_gid) };
    println!("sgx_return: {}", sgx_return);
    println!("epid_gid  : {}", extended_epid_gid);

    // MSG0 is p_extended_epid_group_id 
    // isv_app -> service_provider
    let mut msg = Msg::new();
    msg.set_msg_type(MsgType::SGX_RA_MSG0);
    msg.set_msg_bytes(extended_epid_gid.to_le_bytes().to_vec());
    tx.send((msg,WriteFlags::default())).unwrap();

    let msg0_reply = rx.next().unwrap().unwrap();
    assert_eq!(msg0_reply.get_msg_type(), MsgType::SGX_RA_MSG0_REPLY);
    if msg0_reply.get_msg_bytes() == 0_u32.to_le_bytes() {
        panic!("Oops! AAS rejected msg0!");
    }

    // MSG1 contains g_a (public ephermeral key ECDH for App) and gid (EPID Group ID - For SigRL)
    let mut p_msg1_buf = vec![0; size_of::<sgx_ra_msg1_t>()];
    let sgx_return = unsafe { sgx_ra_get_msg1(ra_context, eid, sgx_ra_get_ga, p_msg1_buf.as_mut_ptr() as *mut sgx_ra_msg1_t) };
    let mut msg = Msg::new();
    msg.set_msg_type(MsgType::SGX_RA_MSG1);
    msg.set_msg_bytes(p_msg1_buf);
    tx.send((msg,WriteFlags::default())).unwrap();

    println!("sgx_return: {}", sgx_return);

    // MSG2 contains g_b (public ephemeral ECDH key for SP), SPID, quote_type,
    // KDF (key derivation function), signed (gb, ga) using SP's non-ephemeral P256 key, MAC, SigRL
    // hdr: usize which tell use what's the size of the object
    let msg2 = rx.next().unwrap().unwrap();
    let p_msg2_ptr = msg2.get_msg_bytes().as_ptr() as *const sgx_ra_msg2_t;
    let msg2_size = msg2.get_msg_bytes().len();
    // prepare pointer to recv p_msg3 and its size.
    let mut p_msg3_ptr: *mut sgx_ra_msg3_t = 0 as *mut sgx_ra_msg3_t;
    let mut msg3_size = 0_u32;
    let sgx_return = unsafe {sgx_ra_proc_msg2(ra_context, eid, sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, p_msg2_ptr, msg2_size as u32 , &mut p_msg3_ptr, &mut msg3_size)};
    println!("sgx_return: {}", sgx_return);
    println!("msg3_size: {}", msg3_size);

    // debug: do an ecall to print the derived keys
    unsafe {print_keys(eid, &mut retval, ra_context)};

    // send msg3 to attestation server
    let msg3_vec = unsafe {core::slice::from_raw_parts(p_msg3_ptr as *const u8, msg3_size as usize).to_vec()};
    let mut msg = Msg::new();
    msg.set_msg_type(MsgType::SGX_RA_MSG3);
    msg.set_msg_bytes(msg3_vec);
    tx.send((msg,WriteFlags::default())).unwrap();

    let msg3_reply = rx.next().unwrap().unwrap();
    assert_eq!(msg3_reply.get_msg_type(), MsgType::SGX_RA_MSG3_REPLY);
    println!("mac: {:02x?}", unsafe{(*p_msg3_ptr).mac});

    if msg3_reply.get_msg_bytes() == 1u32.to_le_bytes() {
        // aas accepted our attestation, we'll prepare the request
        let mut aas_request = CAasRegRequest::default();
        let _ = unsafe {gen_ec256_pubkey(eid, &mut retval, ra_context, &mut aas_request)};
        let p_aas_request = &aas_request as *const CAasRegRequest as *const u8;
        let aas_request_byte_slice = unsafe{core::slice::from_raw_parts(p_aas_request, size_of::<CAasRegRequest>())};

        let mut msg = Msg::new();
        msg.set_msg_type(MsgType::AAS_RA_REG_REQUEST);
        msg.set_msg_bytes(aas_request_byte_slice.to_vec());
        tx.send((msg, WriteFlags::default())).unwrap();

        let msg_aas_report = rx.next().unwrap().unwrap();
        assert_eq!(msg_aas_report.get_msg_type(), MsgType::AAS_RA_REG_REPORT);
        let aas_report_bytes = msg_aas_report.get_msg_bytes();
        let aas_report: AasRegReport = serde_cbor::from_slice(aas_report_bytes).unwrap();
        println!("{:?}", aas_report);

        let srv_pubkey = Secp256r1PublicKey{
        // 04:1a:4f:ea:0d:04:bd:ed:7d:c1:43:ee:74:cb:8e:
        // 56:9e:6e:49:1c:89:bc:d6:5c:34:8f:8a:5b:40:5f:
        // 79:53:e3:89:7d:0f:0c:bc:cf:f0:45:ce:c9:a9:1d:
        // 39:9c:cc:3e:09:ee:b0:2a:b6:d2:8d:dd:67:9b:b4:
        // bb:5c:68:98:9c
            gx:[227, 83, 121, 95, 64, 91, 138, 143, 52, 92, 214, 188, 137, 28, 73, 110, 158, 86, 142, 203, 116, 238, 67, 193, 125, 237, 189, 4, 13, 234, 79, 26],
            gy:[156, 152, 104, 92, 187, 180, 155, 103, 221, 141, 210, 182, 42, 176, 238, 9, 62, 204, 156, 57, 29, 169, 201, 206, 69, 240, 207, 188, 12, 15, 125, 137],
        };
        let report_verify = aas_utils::verify_aas_reg_report(&aas_report, &srv_pubkey);
        println!("report verified: {:?}", report_verify);
        println!("{:?}", srv_pubkey);

    } else {
        println!("AAS rejected our attestation. >.<");
    }


    unsafe{enclave_ra_close(eid, &mut retval, ra_context)};
}
