#!/bin/sh

APPNAME="udp-scan-$(arch)"
STRIP="ppi" #none" #pod"
LINKTYPE="static" #allow-dynamic"
BIN_DIR="bin"
RC_FILE=${HOME}/.staticperlrc
SP_FILE=${HOME}/staticperl
BOOT_FILE="udp-scan.pl"


if [ -f ${RC_FILE} ]; then
	. ${RC_FILE}
else
	echo "${RC_FILE}: not found"
	exit 1
fi

if [ ! -d "${BIN_DIR}" ]; then
	mkdir ${BIN_DIR} || exit 1
fi

${SP_FILE} mkapp ${BIN_DIR}/$APPNAME --boot ${BOOT_FILE} \
-MNet::Ping \
-MIO::Socket \
-MIO::Select \
-MNetPacket::IP \
-MNetPacket::ICMP \
--strip ${STRIP} \
--${LINKTYPE} \
--usepacklists \
$@ || exit 1

strip ${BIN_DIR}/${APPNAME}
upx --best ${BIN_DIR}/${APPNAME}
