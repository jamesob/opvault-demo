FROM docker.io/library/python:3.11-slim-bullseye

ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en

ARG LLVMVER=17
ARG NVIM_VER=master

RUN apt-get update && apt-get install --yes \
    sudo bsdextrautils git \
    zsh cmake curl libtool libtool-bin autoconf automake cmake g++ \
    pkg-config unzip build-essential python3-venv \
    libevent-dev libboost-dev libboost-system-dev libboost-filesystem-dev \
    libboost-test-dev libsqlite3-dev && \
    apt-get purge -y --auto-remove && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en

ENV UNAME=user
ARG UID=1000
ARG GID=1000

RUN git clone --depth 1 https://github.com/jamesob/bitcoin.git /bitcoin -b 2023-02-opvault-inq && \
    cd /bitcoin && \
    ./autogen.sh && \
    ./configure --disable-fuzz-binary --disable-gui-tests --without-gui && \
    make -j && make install

RUN groupadd -g $GID -o $UNAME && \
  useradd -m -u $UID -g $GID -o -d /home/$UNAME -s /bin/bash $UNAME && \
  echo $UNAME:password | chpasswd && \
  adduser $UNAME sudo

USER $UNAME
WORKDIR /home/$UNAME

# The RPC password below is "password"
CMD bitcoind -regtest -fallbackfee=0.00001 -blockfilterindex=1 \
    -rpcbind=0.0.0.0 -rpcallowip=0.0.0.0/0 \
    -rpcauth='user:767f817539fd685c2830cbf46c4a7b83$f3fc01227efb6c67c2ec53a6abc30336a0bd5693de79ae44177795c29c9694b1'
