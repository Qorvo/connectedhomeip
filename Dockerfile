#  Copyright (c) 2022, Qorvo

ARG BASE_IMAGE=registry.gitlab.com/qorvo/wcon/lps_sw/p236_chip/qorvo_crosscompile:latest

FROM ${BASE_IMAGE}

SHELL ["/bin/bash", "-c"]

ADD . /root/repo

RUN apt-get update
RUN apt-get install zip

WORKDIR /opt
COPY install_zap_versions.sh /opt
COPY zap-versions.txt /opt
RUN ./install_zap_versions.sh

WORKDIR /root/repo

RUN source scripts/bootstrap.sh
