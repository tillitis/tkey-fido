// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

#include <lib.h>
#include <tk1_mem.h>

#include "p256-m.h"
#include "sha-256.h"
#include "u2f.h"

// Outline of method for keyhandle generation and private key
// recovery. Hash function used is blake2s.
//
// Start by getting CDI as the secret to be used for keyed blake2s hashing.
//
// On registration
//
// - Our external input is the app_param (32 bytes).
//
// - Create a random nonce (32 bytes).
//
// - Create our private key by doing a keyed hash over (app_param,
//   nonce) using our secret.
//
// - Now create a MAC for the keyhandle, it's a hash over (app_param,
//   private key) using same secret.
//
// - The keyhandle we will output is (nonce, MAC).
//
// On authentication
//
// - External input is the same app_param (32 bytes), challenge_param
//   (32 bytes), and our keyhandle (64 bytes).
//
// - We recover the private key by hashing (app_param, nonce from
//   keyhandle).
//
// - Then recreate the MAC by hashing (app_param, private key) using the same
// - secret.
//
// - Verify the recreated MAC is the same as MAC from keyhandle.

// clang-format off
static volatile uint32_t *cdi =             (volatile uint32_t *)TK1_MMIO_TK1_CDI_FIRST;
static volatile uint32_t *led =             (volatile uint32_t *)TK1_MMIO_TK1_LED;
static volatile uint32_t *touch =           (volatile uint32_t *)TK1_MMIO_TOUCH_STATUS;
static volatile uint32_t *timer =           (volatile uint32_t *)TK1_MMIO_TIMER_TIMER;
static volatile uint32_t *timer_prescaler = (volatile uint32_t *)TK1_MMIO_TIMER_PRESCALER;
static volatile uint32_t *timer_status =    (volatile uint32_t *)TK1_MMIO_TIMER_STATUS;
static volatile uint32_t *timer_ctrl =      (volatile uint32_t *)TK1_MMIO_TIMER_CTRL;

#define LED_BLACK 0
#define LED_RED   (1 << TK1_MMIO_TK1_LED_R_BIT)
#define LED_GREEN (1 << TK1_MMIO_TK1_LED_G_BIT)
#define LED_BLUE  (1 << TK1_MMIO_TK1_LED_B_BIT)
// clang-format on

// TODO define constants for byte lengths?

// TODO how long?
#define U2F_TOUCH_TIMEOUT_SECS 10
// device clock frequency is at 18 MHz
#define TKEY_HZ 18000000

// registration: flashing for touch confirm, steady while generating keypair
#define U2F_REGISTER_LEDVALUE LED_BLUE
// authentication: flashing for touch confirm, steady while signing
#define U2F_AUTHENTICATE_LEDVALUE LED_GREEN

static uint32_t secret[8];

void u2f_init()
{
	// Get the CDI which is used for keyed blake2s hash
	wordcpy(secret, (void *)cdi, 8);
}

static int wait_touched(uint32_t ledvalue)
{
	int touched = 0;

	// make sure timer is stopped
	*timer_ctrl = (1 << TK1_MMIO_TIMER_CTRL_STOP_BIT);
	// timeout in seconds
	*timer_prescaler = TKEY_HZ;
	*timer = U2F_TOUCH_TIMEOUT_SECS;
	// start the timer
	*timer_ctrl = (1 << TK1_MMIO_TIMER_CTRL_START_BIT);

	// first a write, to ensure no stray touch?
	*touch = 0;

	const int loopcount = 130000;
	int led_on = 0;
	for (;;) {
		*led = led_on ? ledvalue : LED_BLACK;
		for (int i = 0; i < loopcount; i++) {
			if ((*timer_status &
			     (1 << TK1_MMIO_TIMER_STATUS_RUNNING_BIT)) == 0) {
				goto done;
			}
			if (*touch & (1 << TK1_MMIO_TOUCH_STATUS_EVENT_BIT)) {
				// write, confirming we read the touch event
				*touch = 0;
				touched = 1;
				goto done;
			}
		}
		led_on = !led_on;
	}
done:
	*led = LED_BLACK;

	return touched;
}

// out: mac: blake2s MAC (32 bytes)
//  in: part1: of hash input (32 bytes)
//      part2: of hash input (32 bytes)
static void blake2s_mac(uint8_t *mac, const uint8_t *part1,
			const uint8_t *part2)
{
	uint8_t in[64];
	static blake2s_ctx b2s_ctx;

	memcpy(in, part1, 32);
	memcpy(in + 32, part2, 32);
	blake2s(mac, 32, secret, 32, in, 64, &b2s_ctx);
}

// out: output: data for response, details below (129 bytes)
//  in: appli_param: from Relying Party (32 bytes)
// return: if successful returns 0 and output is filled, otherwise returns
//         non-zero and output is untouched
int u2f_register(uint8_t *output, const uint8_t *appli_param)
{
	uint8_t nonce[32], priv[32], mac[32], pub[64];

	int user_presence = wait_touched(U2F_REGISTER_LEDVALUE);
	if (user_presence == 0) {
		// return early when no user present
		output[0] = 0;
		return 0;
	}

	*led = U2F_REGISTER_LEDVALUE;

	rng_generate(nonce, 32);

	blake2s_mac(priv, appli_param, nonce);

	// TODO the following can fail, but how likely is it at all? given
	// input is a blake2s MAC. Even p256-m's p256_gen_keypair() function
	// has this issue with random generates bytes -- it retries a few
	// times, but can actually fail. We could also retry with new random
	// nonce.
	//
	// The probability of failing is 1 in:
	// >>>
	// (0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
	// -0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551)
	// /0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
	// 2.3283064359965952e-10
	int ret = p256_keypair_from_bytes(pub, priv);
	if (ret != 0) {
		return ret;
	}

	blake2s_mac(mac, appli_param, priv);

	output[0] = user_presence;
	// now 64 bytes of keyhandle (nonce,MAC)
	memcpy(&output[1], nonce, 32);
	memcpy(&output[1 + 32], mac, 32);
	// and raw pubkey bytes
	memcpy(&output[1 + 32 + 32], pub, 64);
	return 0;
}

// out: payload: for response, details below (1 byte)
//  in: appli_param: from Relying Party (32 bytes)
//      keyhandle: 1st half is nonce, 2nd is MAC (64 bytes)
void u2f_checkonly(uint8_t *payload, const uint8_t *appli_param,
		   const uint8_t *keyhandle)
{
	const uint8_t *nonce = keyhandle;
	const uint8_t *mac = &keyhandle[32];
	uint8_t priv[32], macAgain[32];

	blake2s_mac(priv, appli_param, nonce);
	blake2s_mac(macAgain, appli_param, priv);

	int keyhandle_valid = 1;
	for (int i = 0; i < 32; i++) {
		if (mac[i] != macAgain[i]) {
			keyhandle_valid = 0;
		}
	}

	payload[0] = keyhandle_valid;
}

// out: payload: for response, details below (66 bytes)
//  in: appli_param: from Relying Party (32 bytes)
//      chall_param: from Relying Party (32 bytes)
//      keyhandle: 1st half is nonce, 2nd is MAC (64 bytes)
//      check_user: 1 if user presence should be checked, 0 otherwise (1 byte)
//      counter: number of auth operations, persisted by host-program (4 bytes)
// return: if successful returns 0 and payload is filled, otherwise returns
//         non-zero and payload is untouched
int u2f_authenticate(uint8_t *payload, const uint8_t *appli_param,
		     const uint8_t *chall_param, const uint8_t *keyhandle,
		     const uint8_t *check_user, const uint8_t *counter)
{
	const uint8_t *nonce = keyhandle;
	const uint8_t *mac = &keyhandle[32];
	uint8_t priv[32], macAgain[32];

	blake2s_mac(priv, appli_param, nonce);
	blake2s_mac(macAgain, appli_param, priv);

	int keyhandle_valid = 1;
	for (int i = 0; i < 32; i++) {
		if (mac[i] != macAgain[i]) {
			keyhandle_valid = 0;
		}
	}

	// If keyhandle is not valid we'll return early
	if (keyhandle_valid == 0) {
		// Always returning keyhandle validity (and handling it nicely
		// up in softHID). I guess FIDO clients are supposed to do
		// ctrl-check-only first (the u2f_checkonly function in here),
		// but who knows.
		payload[0] = keyhandle_valid;
		return 0;
	}

	uint8_t user_presence = 0;

	// Should we check if user is present?
	if (*check_user != 0) {
		if (wait_touched(U2F_AUTHENTICATE_LEDVALUE) == 0) {
			// If user is not present we'll return early
			payload[0] = keyhandle_valid;
			payload[1] = user_presence;
			return 0;
		}
		user_presence = 1;
	}

	*led = U2F_AUTHENTICATE_LEDVALUE;

	// appli_param (32), user_presence (1),
	// counter(4, big-endian), chall_param (32)
	uint8_t sig_data[32 + 1 + 4 + 32];
	memcpy(&sig_data[0], appli_param, 32);
	sig_data[32] = user_presence;
	memcpy(&sig_data[32 + 1], counter, 4);
	memcpy(&sig_data[32 + 1 + 4], chall_param, 32);

	uint8_t hash[32];
	calc_sha_256(hash, sig_data, 32 + 1 + 4 + 32);

	uint8_t sig[64];
	int res = p256_ecdsa_sign(sig, priv, hash, 32);
	if (res != 0) {
		// TODO use some specific non-zero value, or fail in some other
		// way? What should the response over HID be, really?
		return res;
	}

	payload[0] = keyhandle_valid;
	payload[1] = user_presence;
	memcpy(&payload[2], sig, 64);
	return 0;
}
