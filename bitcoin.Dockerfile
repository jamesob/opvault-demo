FROM docker.io/archlinux:latest

ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en

RUN pacman -Syyu --noconfirm && pacman -Sy --noconfirm --needed \
        autoconf automake boost gcc git libevent libtool make pkgconf python sqlite && \
    git clone https://github.com/jamesob/bitcoin.git /bitcoin && \
    cd /bitcoin && \
    git checkout 2023-02-opvault-inq && \
    ./autogen.sh && \
    ./configure && \
    make -j

WORKDIR /bitcoin
CMD ./src/bitcoind -regtest -fallbackfee=0.00001 -blockfilterindex=1 \
    -rpcbind=0.0.0.0 -rpcallowip=0.0.0.0/0 \
    -rpcauth='user:767f817539fd685c2830cbf46c4a7b83$f3fc01227efb6c67c2ec53a6abc30336a0bd5693de79ae44177795c29c9694b1'
