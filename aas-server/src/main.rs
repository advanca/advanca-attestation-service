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

use ctrlc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use env_logger;
use log::{debug, error, info, trace};

use futures::*;

use async_std::task;

<<<<<<< HEAD
=======
use aas_protos_std::aas::aas::*;
>>>>>>> 8ee5d2c083f12677b9451d134216901913887c3d
use aas_protos_std::aas::aas::Msg_MsgType as MsgType;
use aas_protos_std::aas::aas::*;
use aas_protos_std::aas::aas_grpc::{self, AasServer};

use grpcio::*;

use advanca_crypto::*;
use advanca_crypto_types::*;

use structopt::StructOpt;
use hex;
use sgx_ra;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(about = "aas-server usage")]
struct Opt {
    #[structopt(
        long = "conditional-secure",
        help = "treat conditional secure IAS response as secure"
    )]
    conditional_secure: bool,
    #[structopt(
        short = "p",
        long = "port",
        default_value = "11800",
        help = "aas-server listening port"
    )]
    aas_port: u16,
}

#[derive(Debug, StructOpt)]
#[structopt(about = "aas-server usage")]
struct Opt {
    #[structopt(
        long = "conditional-secure",
        help = "treat conditional secure IAS response as secure"
    )]
    conditional_secure: bool,
    #[structopt(
        short = "p",
        long = "port",
        default_value = "11800",
        help = "aas-server listening port"
    )]
    aas_port: u16,
}

#[derive(Clone, Default)]
struct AasServerService {
    conditional_secure: bool,
    aas_prvkey_der: Vec<u8>,
    spid: Vec<u8>,
    ias_apikey_str: String,
}

impl AasServer for AasServerService {
<<<<<<< HEAD
    fn timestamp(
=======
    fn timestamp (
>>>>>>> 8ee5d2c083f12677b9451d134216901913887c3d
        &mut self,
        ctx: RpcContext,
        timestamp_request: TimestampRequest,
        sink: UnarySink<TimestampResponse>,
    ) {
        let aas_timestamp = AasTimestamp {
<<<<<<< HEAD
            timestamp: std::time::SystemTime::now()
=======
            timestamp : std::time::SystemTime::now()
>>>>>>> 8ee5d2c083f12677b9451d134216901913887c3d
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            data: timestamp_request.data,
        };
        let aas_prvkey = Secp256r1PrivateKey::from_der(&self.aas_prvkey_der);
<<<<<<< HEAD
        let aas_timestamp_bytes = serde_cbor::to_vec(&aas_timestamp).unwrap();
        let signed_timestamp = secp256r1_sign_msg(&aas_prvkey, &aas_timestamp_bytes).unwrap();
        let mut timestamp_response = TimestampResponse::new();
        timestamp_response.signed_data = serde_cbor::to_vec(&signed_timestamp).unwrap();
        let f = sink
            .success(timestamp_response.clone())
=======
        let aas_timestamp_bytes = serde_json::to_vec(&aas_timestamp).unwrap();
        let signed_timestamp = secp256r1_sign_msg(&aas_prvkey, &aas_timestamp_bytes).unwrap();
        let mut timestamp_response = TimestampResponse::new();
        timestamp_response.signed_data = serde_json::to_vec(&signed_timestamp).unwrap();
        let f = sink.success(timestamp_response.clone())
>>>>>>> 8ee5d2c083f12677b9451d134216901913887c3d
            .map_err(move |err| error!("failed to reply: {:?}", err))
            .map(move |_| trace!("replied with {:?}", timestamp_response));
        ctx.spawn(f)
    }

    fn remote_attest(
        &mut self,
        _ctx: RpcContext,
        msg_in: RequestStream<Msg>,
        msg_out: DuplexSink<Msg>,
    ) {
        let mut msg_in = msg_in;
        let mut msg_out = msg_out;
        let conditional_secure = self.conditional_secure;
        let aas_prvkey_der = self.aas_prvkey_der.clone();
        let spid = self.spid.clone();
        let ias_apikey_str = self.ias_apikey_str.clone();
        // we won't be using the grpcio polling thread,
        // instead we'll use our own thread. otherwise
        // deadlock when we block on the msg_in.
        thread::spawn(move || {
            task::block_on(async move {
                // initialize the session
                debug!("SPID  : {:?}", spid);
                debug!("APIKEY: {:?}", ias_apikey_str);
                let is_dev = true;
                let mut session =
                    sgx_ra::sp_init_ra(&aas_prvkey_der, &spid, &ias_apikey_str, is_dev);

                // get msg0 and msg1 from the attestee
                let msg0 = msg_in.next().await.unwrap().unwrap();
                info!("[worker]---[msg0]------------->[aas]                      [ias]");
                assert_eq!(MsgType::SGX_RA_MSG0, msg0.get_msg_type());

                if sgx_ra::sp_proc_ra_msg0(msg0.get_msg_bytes()) {
                    let mut msg = Msg::new();
                    msg.set_msg_type(MsgType::SGX_RA_MSG0_REPLY);
                    msg.set_msg_bytes(1_u32.to_le_bytes().to_vec());
                    let _ = msg_out
                        .send((msg.to_owned(), WriteFlags::default()))
                        .await
                        .unwrap();
                } else {
                    let mut msg = Msg::new();
                    msg.set_msg_type(MsgType::SGX_RA_MSG0_REPLY);
                    msg.set_msg_bytes(0_u32.to_le_bytes().to_vec());
                    let _ = msg_out
                        .send((msg.to_owned(), WriteFlags::default()))
                        .await
                        .unwrap();
                }
                info!("[worker]<--[msg0_reply]--------[aas]                      [ias]");

                let msg1 = msg_in.next().await.unwrap().unwrap();
                info!("[worker]---[msg1]------------->[aas]                      [ias]");
                assert_eq!(MsgType::SGX_RA_MSG1, msg1.get_msg_type());
                let msg2_bytes = sgx_ra::sp_proc_ra_msg1(msg1.get_msg_bytes(), &mut session);

                let mut msg = Msg::new();
                msg.set_msg_type(MsgType::SGX_RA_MSG2);
                msg.set_msg_bytes(msg2_bytes);
                let _ = msg_out
                    .send((msg.to_owned(), WriteFlags::default()))
                    .await
                    .unwrap();
                info!("[worker]<--[msg2]--------------[aas]                      [ias]");

                // at this point we have derived the secret keys and we'll wait for the attestee to
                // send us msg3, after which we will forward to ias to verify the sgx platform.
                let msg3 = msg_in.next().await.unwrap().unwrap();
                let ias = sgx_ra::sp_proc_ra_msg3(msg3.get_msg_bytes(), &mut session).unwrap();
                let quote = ias.get_isv_enclave_quote_body();
                let is_secure = ias.is_enclave_secure(conditional_secure);
                let is_debug = quote.is_enclave_debug();
                debug!("ias: {:?}", ias.isv_enclave_quote_status);
                debug!("ias: {:?}", ias.advisory_ids);
                debug!("ias: {:?}", ias.platform_info_blob);
                info!("is_secure: {:?}", &is_secure);
                info!("is_debug : {:?}", &is_debug);
                info!("is_init  : {:?}", quote.is_enclave_init());
                info!("mrenclave: {:02x?}", quote.get_mr_enclave());
                info!("mrsigner : {:02x?}", quote.get_mr_signer());

                // verify mrenclave, mrsigner, is_secure, is_debug
                // TODO: we'll ignore debug flag for eval purposes.
                // let is_verified = is_secure && !is_debug;
                let is_verified = is_secure;
                debug!("is_enclave_verified: {:?}", is_verified);

                if is_verified {
                    // sends the ok message and recv the request
                    let mut msg = Msg::new();
                    msg.set_msg_type(MsgType::SGX_RA_MSG3_REPLY);
                    msg.set_msg_bytes(1_u32.to_le_bytes().to_vec());
                    let _ = msg_out
                        .send((msg.to_owned(), WriteFlags::default()))
                        .await
                        .unwrap();
                    info!("[worker]<--[attest_result:1]---[aas]                      [ias]");

                    let msg_reg_request = msg_in.next().await.unwrap().unwrap();
                    info!("[worker]---[aas_reg_request]-->[aas]                      [ias]");
                    assert_eq!(MsgType::AAS_RA_REG_REQUEST, msg_reg_request.get_msg_type());

                    let reg_request_bytes = msg_reg_request.get_msg_bytes();
                    // assert_eq!(reg_request_bytes.len(), size_of::<CAasRegRequest>());

                    let reg_request: AasRegRequest =
                        serde_json::from_slice(&reg_request_bytes).unwrap();
                    let reg_report =
                        sgx_ra::sp_proc_aas_reg_request(&reg_request, &session).unwrap();
                    let msg_bytes = serde_json::to_vec(&reg_report).unwrap();
                    let mut msg = Msg::new();
                    msg.set_msg_type(MsgType::AAS_RA_REG_REPORT);
                    msg.set_msg_bytes(msg_bytes);
                    let _ = msg_out
                        .send((msg.to_owned(), WriteFlags::default()))
                        .await
                        .unwrap();
                    info!("[worker]<--[aas_reg_report]----[aas]                      [ias]");
                } else {
                    // sends the nok message and terminate
                    let mut msg = Msg::new();
                    msg.set_msg_type(MsgType::SGX_RA_MSG3_REPLY);
                    msg.set_msg_bytes(0_u32.to_le_bytes().to_vec());
                    let _ = msg_out
                        .send((msg.to_owned(), WriteFlags::default()))
                        .await
                        .unwrap();
                    info!("[worker]<--[attest_result:0]---[aas]                      [ias]");
                    let platform_info_blob = hex::decode(ias.platform_info_blob.unwrap()).unwrap();
                    debug!("platform_info_blob: {:?}", platform_info_blob);
                    let mut msg = Msg::new();
                    msg.set_msg_type(MsgType::AAS_RA_TCB_UPDATE);
                    msg.set_msg_bytes(platform_info_blob);
                    let _ = msg_out
                        .send((msg.to_owned(), WriteFlags::default()))
                        .await
                        .unwrap();
                }
                msg_out.close().await.unwrap();
            });
        });
    }
}

fn main() {
    let opt = Opt::from_args();
    env_logger::init();
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let aas_prvkey_der = std::fs::read("sp_prv.der").unwrap();
    let spid_hex = std::fs::read_to_string("sp_ias_spid.txt").unwrap();
    let spid_hex = spid_hex.trim();
    let spid = hex::decode(spid_hex).unwrap();
    let ias_apikey_str = std::fs::read_to_string("sp_ias_apikey.txt").unwrap();

    let env = Arc::new(Environment::new(4));
    let instance = AasServerService {
<<<<<<< HEAD
        conditional_secure: opt.conditional_secure,
=======
        conditional_secure : opt.conditional_secure,
>>>>>>> 8ee5d2c083f12677b9451d134216901913887c3d
        aas_prvkey_der: aas_prvkey_der,
        spid: spid,
        ias_apikey_str: ias_apikey_str,
    };
    let service = aas_grpc::create_aas_server(instance);
    let mut server = ServerBuilder::new(env)
        .register_service(service)
        .bind("0.0.0.0", opt.aas_port)
        .build()
        .unwrap();
    server.start();

    println!("Press Ctrl-C to stop");
    while running.load(Ordering::SeqCst) {}

    task::block_on(async move {
        let _ = server.shutdown().await;
    });
}
