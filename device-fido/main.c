// Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

#include <monocypher/monocypher-ed25519.h>
#include <qemu_debug.h>
#include <tk1_mem.h>

#include "app_proto.h"
#include "rng.h"
#include "u2f.h"

// clang-format off
static volatile uint32_t *led =   (volatile uint32_t *)TK1_MMIO_TK1_LED;

#define LED_BLACK 0
#define LED_RED   (1 << TK1_MMIO_TK1_LED_R_BIT)
#define LED_GREEN (1 << TK1_MMIO_TK1_LED_G_BIT)
#define LED_BLUE  (1 << TK1_MMIO_TK1_LED_B_BIT)
// clang-format on

const uint8_t app_name0[4] = "tk1 ";
const uint8_t app_name1[4] = "fido";
const uint32_t app_version = 0x00000001;

// steady color for app waiting for cmd
#define APP_LEDVALUE (LED_RED | LED_GREEN) // yellow

int main(void)
{
	struct frame_header hdr; // Used in both directions
	uint8_t cmd[CMDLEN_MAXBYTES];
	uint8_t rsp[CMDLEN_MAXBYTES];
	uint8_t in;
	uint8_t data[133];

	rng_init_state();
	u2f_init();

	for (;;) {
		*led = APP_LEDVALUE;
		in = readbyte();
		qemu_puts("Read byte: ");
		qemu_puthex(in);
		qemu_lf();

		if (parseframe(in, &hdr) == -1) {
			qemu_puts("Couldn't parse header\n");
			continue;
		}

		memset(cmd, 0, CMDLEN_MAXBYTES);
		// Read app command, blocking
		read(cmd, hdr.len);

		if (hdr.endpoint == DST_FW) {
			appreply_nok(hdr);
			qemu_puts("Responded NOK to message meant for fw\n");
			continue;
		}

		// Is it for us?
		if (hdr.endpoint != DST_SW) {
			qemu_puts("Message not meant for app. endpoint was 0x");
			qemu_puthex(hdr.endpoint);
			qemu_lf();
			continue;
		}

		// Reset response buffer
		memset(rsp, 0, CMDLEN_MAXBYTES);

		// Min length is 1 byte so this should always be here
		switch (cmd[0]) {
		case APP_CMD_GET_NAMEVERSION:
			qemu_puts("APP_CMD_GET_NAMEVERSION\n");
			// only zeroes if unexpected cmdlen bytelen
			if (hdr.len == 1) {
				memcpy(&rsp[0], app_name0, 4);
				memcpy(&rsp[4], app_name1, 4);
				memcpy(&rsp[8], &app_version, 4);
			}
			appreply(hdr, APP_RSP_GET_NAMEVERSION, rsp);
			break;

		case APP_CMD_U2F_REGISTER: {
			qemu_puts("APP_CMD_U2F_REGISTER\n");
			if (hdr.len != 128) {
				rsp[0] = STATUS_BAD;
				appreply(hdr, APP_RSP_U2F_REGISTER, rsp);
				break;
			}

			uint8_t output[129];
			int ret = u2f_register(output,
					       &cmd[1] // appli_param
			);
			*led = LED_BLACK;
			if (ret != 0) {
				rsp[0] = STATUS_BAD;
				rsp[1] = ret;
				appreply(hdr, APP_RSP_U2F_REGISTER, rsp);
				break;
			}

			// TODO because we have a lot of data we send 2
			// responses to a single cmd

			// 1st response: user_presence and keyhandle
			rsp[0] = STATUS_OK;
			memcpy(&rsp[1], &output[0], 1 + 64);
			appreply(hdr, APP_RSP_U2F_REGISTER, rsp);

			// 2nd response: pubkey
			rsp[0] = STATUS_OK;
			memcpy(&rsp[1], &output[1 + 64], 64);
			appreply(hdr, APP_RSP_U2F_REGISTER, rsp);
			break;
		}

		case APP_CMD_U2F_CHECKONLY: {
			qemu_puts("APP_CMD_U2F_CHECKONLY\n");
			if (hdr.len != 128) {
				rsp[0] = STATUS_BAD;
				appreply(hdr, APP_RSP_U2F_CHECKONLY, rsp);
				break;
			}

			u2f_checkonly(&rsp[1],
				      &cmd[1],	   // appli_param
				      &cmd[1 + 32] // keyhandle
			);

			rsp[0] = STATUS_OK;
			// rsp[1] is set by u2f_checkonly() to a bool
			// indicating whether the keyhandle is valid (value 1)
			// or not (value 0).
			appreply(hdr, APP_RSP_U2F_CHECKONLY, rsp);
			break;
		}

		// TODO We need to receive >127 bytes of data, so we have both
		// AUTHENTICATE_SET and AUTHENTICATE_GO. We should have a state
		// machine that after a SET cmd only allows GO (GO without a
		// SET first is also an error).
		case APP_CMD_U2F_AUTHENTICATE_SET: {
			qemu_puts("APP_CMD_U2F_AUTHENTICATE_SET\n");
			if (hdr.len != 128) {
				rsp[0] = STATUS_BAD;
				appreply(hdr, APP_RSP_U2F_AUTHENTICATE, rsp);
				break;
			}

			// pick up appli_param, chall_param
			memcpy(data, &cmd[1], 32 + 32);
			rsp[0] = STATUS_OK;
			appreply(hdr, APP_RSP_U2F_AUTHENTICATE, rsp);
			break;
		}

		case APP_CMD_U2F_AUTHENTICATE_GO: {
			qemu_puts("APP_CMD_U2F_AUTHENTICATE_GO\n");
			if (hdr.len != 128) {
				rsp[0] = STATUS_BAD;
				appreply(hdr, APP_RSP_U2F_AUTHENTICATE, rsp);
				break;
			}

			// pick up keyhandle, check_user, counter
			memcpy(&data[32 + 32], &cmd[1], 64 + 1 + 4);

			int ret = u2f_authenticate(&rsp[1],
						   &data[0],   // appli_param
						   &data[32],  // chall_param
						   &data[64],  // keyhandle
						   &data[128], // check_user
						   &data[129]  // counter
			);

			*led = LED_BLACK;
			if (ret != 0) {
				rsp[0] = STATUS_BAD;
				rsp[1] = ret;
				appreply(hdr, APP_RSP_U2F_AUTHENTICATE, rsp);
				break;
			}

			rsp[0] = STATUS_OK;
			// payload has been filled out by u2f_authenticate()
			appreply(hdr, APP_RSP_U2F_AUTHENTICATE, rsp);
			break;
		}

		default:
			qemu_puts("Received unknown command: ");
			qemu_puthex(cmd[0]);
			qemu_lf();
			appreply(hdr, APP_RSP_UNKNOWN_CMD, rsp);
		}
	}
}
