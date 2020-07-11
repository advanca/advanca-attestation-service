FROM rust:1.44.0 as builder
LABEL maintainer "Advanca Authors"
LABEL description="This is the build stage for advanca-attestation-service"

ARG PROFILE=release
ARG SGX_SDK_BIN=sgx_linux_x64_sdk_2.9.101.2.bin
ARG SGX_SDK_URL=https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.9.101.2.bin

WORKDIR /advanca

COPY . /advanca

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential cmake pkg-config protobuf-compiler \
    && curl -sO ${SGX_SDK_URL} \
    && chmod +x ${SGX_SDK_BIN} \
    && echo -e 'no\n/opt/intel' | ./${SGX_SDK_BIN}

RUN rustup default nightly-2020-04-07-x86_64-unknown-linux-gnu
RUN cargo install -f cargo
RUN cargo build --$PROFILE

# ===== SECOND STAGE ======

FROM rust:1.44.0-slim
LABEL maintainer "Advanca Authors"
LABEL description="This is the 2nd stage"

ARG PROFILE=release
COPY --from=builder /advanca/target/$PROFILE/aas-server /usr/local/bin

RUN	useradd -m -u 1000 -U -s /bin/sh -d /advanca advanca

USER advanca
EXPOSE 11800

# Three files are required under this WORKDIR for a successful launch
# - sp_ias_apikey.txt
# - sp_ias_spid.txt
# - sp_prv_pk8.der

WORKDIR /advanca
VOLUME ["/advanca"]

ENTRYPOINT ["/usr/local/bin/aas-server"]
