// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

#include <types.h>

void u2f_init();

int u2f_register(uint8_t *payload, const uint8_t *appli_param);

void u2f_checkonly(uint8_t *payload, const uint8_t *appli_param,
		   const uint8_t *keyhandle);

int u2f_authenticate(uint8_t *payload, const uint8_t *appli_param,
		     const uint8_t *chall_param, const uint8_t *keyhandle,
		     const uint8_t *check_user, const uint8_t *counter);
