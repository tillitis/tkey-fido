// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

#include <types.h>

void rng_init_state();
int rng_generate(uint8_t *output, unsigned output_size);
