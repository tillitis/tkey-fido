// Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

// rng stream extraction app.
//
// When loaded and started, this app will continiously generate random data
// words and send them to the host as a stream of bytes.

#include <blake2s.h>
#include <lib.h>
#include <tk1_mem.h>

#include "rng.h"

#define RESEED_TIME 1000

// clang-format off
static volatile uint32_t *cdi =            (volatile uint32_t *)TK1_MMIO_TK1_CDI_FIRST;
static volatile uint32_t *trng_status =    (volatile uint32_t *)TK1_MMIO_TRNG_STATUS;
static volatile uint32_t *trng_entropy =   (volatile uint32_t *)TK1_MMIO_TRNG_ENTROPY;
// clang-format on

// state context
typedef struct {
	uint32_t ctr;
	uint32_t state[16];
} rng_ctx;

static uint32_t digest[8];
static rng_ctx ctx;
static blake2s_ctx b2s_ctx;

uint32_t get_w32_entropy()
{
	while (!*trng_status) {
	}
	return *trng_entropy;
}

void rng_init_state()
{
	for (int i = 0; i < 8; i++) {
		ctx.state[i] = cdi[i];
		ctx.state[i + 8] = get_w32_entropy();
	}

	ctx.ctr = 0;
}

void update_rng_state(uint32_t *digest)
{
	for (int i = 0; i < 8; i++) {
		ctx.state[i] = digest[i];
	}

	ctx.ctr += 1;
	ctx.state[15] += ctx.ctr;

	if (ctx.ctr == RESEED_TIME) {
		for (int i = 0; i < 8; i++) {
			ctx.state[i + 8] = get_w32_entropy();
		}
		ctx.ctr = 0;
	}
}

void output_w32(uint8_t *output, uint32_t w)
{
	output[0] = w >> 24;
	output[1] = (w >> 16) & 0xff;
	output[2] = (w >> 8) & 0xff;
	output[3] = w & 0xff;
}

// TODO handles only output_size divisable by 16, so we can quickly reuse
// rng_stream code straight up
int rng_generate(uint8_t *output, unsigned output_size)
{
	if (output_size == 0) {
		return 0;
	}
	if (output_size % 16) {
		return -1;
	}

	for (int b = 0; b < output_size / 16; b++) {
		blake2s(&digest[0], 32, NULL, 0, &ctx.state[0], 64, &b2s_ctx);
		// output 16 bytes
		for (int i = 0; i < 4; i++) {
			output_w32(output + b * 16 + i * 4, digest[i]);
		}
		update_rng_state(&digest[0]);
	}

	return 0;
}
