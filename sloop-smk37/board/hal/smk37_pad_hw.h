/* SPDX-License-Identifier: GPL-3.0-only
 * SLOOP for SMK-37 Pro: the pad RGB output. [UNVERIFIED] -- the hardware path
 * is not known yet (see docs/port-evidence.md, pad LEDs; docs/gap-analysis.md).
 *
 * The stock v15 firmware has no decoded pad-colour ABI in this repository
 * (baselines/v15/analysis/subsystem-feasibility/ui.md, LED row: "ABI unknown").
 * Guessing a protocol could drive the wrong pins, so the default is NONE: the
 * colours are computed every scan (smk37_pad_rgb.h) and the pads show their state
 * only through the matrix LED line that SMK37_LEDMAP names.
 *
 * To enable a backend, write the bring-up result here, set
 * SMK37_PAD_HW to that backend, and add its test. Nothing else changes.
 */
#pragma once
#include <stdint.h>

#define SMK37_PAD_HW_NONE 0   /* default: no pad RGB output (unverified path) */
#ifndef SMK37_PAD_HW
#define SMK37_PAD_HW SMK37_PAD_HW_NONE
#endif

static void smk37_pad_hw_write(const uint8_t out[16][3])
{
#if SMK37_PAD_HW == SMK37_PAD_HW_NONE
    (void)out;
#else
#error "no pad RGB backend is verified yet: see docs/port-evidence.md"
#endif
}
