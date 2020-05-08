// This file is generated. Do not edit
// @generated

// https://github.com/Manishearth/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![cfg_attr(rustfmt, rustfmt_skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]

const METHOD_AAS_SERVER_REMOTE_ATTEST: ::grpcio::Method<super::aas::Msg, super::aas::Msg> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Duplex,
    name: "/aas.AasServer/remote_attest",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

#[derive(Clone)]
pub struct AasServerClient {
    client: ::grpcio::Client,
}

impl AasServerClient {
    pub fn new(channel: ::grpcio::Channel) -> Self {
        AasServerClient {
            client: ::grpcio::Client::new(channel),
        }
    }

    pub fn remote_attest_opt(&self, opt: ::grpcio::CallOption) -> ::grpcio::Result<(::grpcio::ClientDuplexSender<super::aas::Msg>, ::grpcio::ClientDuplexReceiver<super::aas::Msg>)> {
        self.client.duplex_streaming(&METHOD_AAS_SERVER_REMOTE_ATTEST, opt)
    }

    pub fn remote_attest(&self) -> ::grpcio::Result<(::grpcio::ClientDuplexSender<super::aas::Msg>, ::grpcio::ClientDuplexReceiver<super::aas::Msg>)> {
        self.remote_attest_opt(::grpcio::CallOption::default())
    }
    pub fn spawn<F>(&self, f: F) where F: ::futures::Future<Item = (), Error = ()> + Send + 'static {
        self.client.spawn(f)
    }
}

pub trait AasServer {
    fn remote_attest(&mut self, ctx: ::grpcio::RpcContext, stream: ::grpcio::RequestStream<super::aas::Msg>, sink: ::grpcio::DuplexSink<super::aas::Msg>);
}

pub fn create_aas_server<S: AasServer + Send + Clone + 'static>(s: S) -> ::grpcio::Service {
    let mut builder = ::grpcio::ServiceBuilder::new();
    let mut instance = s;
    builder = builder.add_duplex_streaming_handler(&METHOD_AAS_SERVER_REMOTE_ATTEST, move |ctx, req, resp| {
        instance.remote_attest(ctx, req, resp)
    });
    builder.build()
}
