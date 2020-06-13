#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
extern crate sgx_tstd as std;

//use protobuf_sgx as protobuf;
extern crate protobuf_sgx as protobuf;

pub mod aas;
