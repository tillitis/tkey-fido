// Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

#ifndef APP_PROTO_H
#define APP_PROTO_H

#include <lib.h>
#include <proto.h>

// TODO lets create #defines for {CMD,RSP}_foo_{LEN,BYTELEN}?

// clang-format off
enum appcmd {
	APP_CMD_GET_NAMEVERSION      = 0x01,
	APP_RSP_GET_NAMEVERSION      = 0x02,
	APP_CMD_U2F_REGISTER         = 0x03,
	APP_RSP_U2F_REGISTER         = 0x04,
	APP_CMD_U2F_CHECKONLY        = 0x05,
	APP_RSP_U2F_CHECKONLY        = 0x06,
	APP_CMD_U2F_AUTHENTICATE_SET = 0x07,
	APP_CMD_U2F_AUTHENTICATE_GO  = 0x08,
	APP_RSP_U2F_AUTHENTICATE     = 0x09,

	APP_RSP_UNKNOWN_CMD = 0xff,
};
// clang-format on

void appreply_nok(struct frame_header hdr);
void appreply(struct frame_header hdr, enum appcmd rspcode, void *buf);

#endif
