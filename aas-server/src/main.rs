pub mod aas_protos;

use std::fs;
use std::thread;
use std::sync::Arc;

use core::mem::size_of;

use std::io::{Read};

use futures::*;
use futures::stream::Stream;
use futures::sink::Sink;
use futures::sync::oneshot;

use crate::aas_protos::aas::{Msg};
use crate::aas_protos::aas_grpc::{self, AasServer};

use crate::aas_protos::aas::Msg_MsgType as MsgType;

use grpcio::*;

use advanca_crypto_ctypes::*;


use hex;
use sgx_ra;

#[derive(Clone,Default)]
struct AasServerService {
}

impl AasServer for AasServerService {
    fn remote_attest (
        &mut self,
        _ctx: RpcContext,
        msg_in: RequestStream<Msg>,
        msg_out: DuplexSink<Msg>,) {

        // we won't be using the grpcio polling thread,
        // instead we'll use our own thread and block
        // on the messages, making it a single, bi-direction
        // protocol exchange between the attestee and us.
        thread::spawn(move || {
            // msg_in  : blocking iterator
            // msg_out : blocking stream
            let mut msg_in = msg_in.wait();
            let mut msg_out = msg_out.wait();

            // initialize the session
            let aas_prvkey_der = fs::read("sp_prv_pk8.der").unwrap();
            let spid_hex = fs::read_to_string("sp_ias_spid.txt").unwrap();
            let spid_hex = spid_hex.trim();
            let spid = hex::decode(spid_hex).unwrap();
            let ias_apikey_str = fs::read_to_string("sp_ias_apikey.txt").unwrap();
            let is_dev = true;
            let mut session = sgx_ra::sp_init_ra(&aas_prvkey_der, &spid, &ias_apikey_str, is_dev);

            // get msg0 and msg1 from the attestee
            let msg0 = msg_in.next().unwrap().unwrap();
            assert_eq!(MsgType::SGX_RA_MSG0, msg0.get_msg_type());

            if sgx_ra::sp_proc_ra_msg0(msg0.get_msg_bytes()) {
                let mut msg = Msg::new();
                msg.set_msg_type(MsgType::SGX_RA_MSG0_REPLY);
                msg.set_msg_bytes(1_u32.to_le_bytes().to_vec());
                let _ = msg_out.send((msg.to_owned(),WriteFlags::default())).unwrap();
            } else {
                let mut msg = Msg::new();
                msg.set_msg_type(MsgType::SGX_RA_MSG0_REPLY);
                msg.set_msg_bytes(0_u32.to_le_bytes().to_vec());
                let _ = msg_out.send((msg.to_owned(),WriteFlags::default())).unwrap();
            }

            let msg1 = msg_in.next().unwrap().unwrap();
            assert_eq!(MsgType::SGX_RA_MSG1, msg1.get_msg_type());
            let msg2_bytes = sgx_ra::sp_proc_ra_msg1(msg1.get_msg_bytes(), &mut session);

            let mut msg = Msg::new();
            msg.set_msg_type(MsgType::SGX_RA_MSG2);
            msg.set_msg_bytes(msg2_bytes);
            let _ = msg_out.send((msg.to_owned(),WriteFlags::default())).unwrap();

            // at this point we have derived the secret keys and we'll wait for the attestee to
            // send us msg3, after which we will forward to ias to verify the sgx platform.
            let msg3 = msg_in.next().unwrap().unwrap();
            let ias = sgx_ra::sp_proc_ra_msg3(msg3.get_msg_bytes(), &mut session);
            let quote = ias.get_isv_enclave_quote_body();
            let is_secure = ias.is_enclave_secure(true);
            let is_debug = quote.is_enclave_debug();
            println!("is_secure: {:?}", &is_secure);
            println!("is_debug : {:?}", &is_debug);
            println!("is_init  : {:?}", quote.is_enclave_init());
            println!("mrenclave: {:02x?}", quote.get_mr_enclave());
            println!("mrsigner : {:02x?}", quote.get_mr_signer());

            // verify mrenclave, mrsigner, is_secure, is_debug
            // TODO: we'll ignore debug flag for eval purposes.
            // let is_verified = is_secure && !is_debug;
            let is_verified = is_secure;

            if is_verified {
                // sends the ok message and recv the request
                let mut msg = Msg::new();
                msg.set_msg_type(MsgType::SGX_RA_MSG3_REPLY);
                msg.set_msg_bytes(1_u32.to_le_bytes().to_vec());
                let _ = msg_out.send((msg.to_owned(),WriteFlags::default())).unwrap();

                let msg_reg_request = msg_in.next().unwrap().unwrap();
                assert_eq!(MsgType::AAS_RA_REG_REQUEST, msg_reg_request.get_msg_type());
                let reg_request_bytes = msg_reg_request.get_msg_bytes();
                assert_eq!(reg_request_bytes.len(), size_of::<CAasRegRequest>());
                let p_reg_request = unsafe{*(reg_request_bytes.as_ptr() as *const CAasRegRequest)};
                let reg_report = sgx_ra::sp_proc_aas_reg_request(&p_reg_request, &session).unwrap();
                let msg_bytes = serde_cbor::to_vec(&reg_report).unwrap();
                let mut msg = Msg::new();
                msg.set_msg_type(MsgType::AAS_RA_REG_REPORT);
                msg.set_msg_bytes(msg_bytes);
                let _ = msg_out.send((msg.to_owned(), WriteFlags::default())).unwrap();
            } else {
                // sends the nok message and terminate
                let mut msg = Msg::new();
                msg.set_msg_type(MsgType::SGX_RA_MSG3_REPLY);
                msg.set_msg_bytes(0_u32.to_le_bytes().to_vec());
                let _ = msg_out.send((msg.to_owned(),WriteFlags::default())).unwrap();
            }
        });
    }
}

fn main() {
    let env = Arc::new(Environment::new(4));
    let instance = AasServerService::default();
    let service = aas_grpc::create_aas_server(instance);
    let mut server = ServerBuilder::new(env)
        .register_service(service)
        .bind("127.0.0.1", 12345)
        .build()
        .unwrap();
    server.start();
    let (tx, rx) = oneshot::channel();
    thread::spawn(|| {
        println!("Press enter to exit...");
        let _ = std::io::stdin().read(&mut [0]).unwrap();
        tx.send(()).unwrap();
        ()
    });
    let _ = rx.wait();
    let _ = server.shutdown().wait();
}
