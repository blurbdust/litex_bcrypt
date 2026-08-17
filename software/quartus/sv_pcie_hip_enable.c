/*
 * sv_pcie_hip_enable.c - let Quartus place a PCIe hard IP block it reports as disabled.
 *
 * This file is part of LiteX-Bcrypt.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Why this exists
 * ---------------
 * On the Microsoft/HP "Storey Peak" (X930613-001, Stratix V 5SGSMD5), edge-connector lanes 0-7 are
 * wired to `pcie_x8` connector 0. Lane 0 is PIN_AV2, whose receiver channel belongs to a PCIe hard
 * IP block that Quartus's device database marks as disabled for this part. Any attempt to fit a
 * design there fails before placement begins:
 *
 *   Error (14566): The Fitter cannot place 1 periphery component(s) due to conflicts with existing
 *                  constraints (1 Receiver channel(s)).
 *   Error (175020): The Fitter cannot place logic Receiver channel in region (202, 13) to
 *                   (202, 15), to which it is constrained, because there are no valid locations in
 *                   the region for logic of this type.
 *   Error (11802): Can't fit design in device.
 *
 * Connector 1 sits on a block Quartus will place, but a x16 card in a slot wired for x8 only has
 * edge lanes 0-7 connected, so a design on connector 1 trains at width x0. Connector 0 is the half
 * that is physically usable, which is why this is not simply avoidable.
 *
 * What it does
 * ------------
 * Quartus asks its device database whether a given hardware block is enabled, via
 * `DEV_DIE_INFO::is_global_id_enabled(unsigned)` in libddb_dev.so. Preloaded ahead of that library,
 * this interposer answers "enabled" for the one block in question and forwards every other query
 * unchanged to the real implementation.
 *
 * Nothing is written to disk and no Quartus file is modified. The effect lasts only for the lifetime
 * of the preloaded process. You are, however, using a block the vendor marked disabled for this
 * device: it is untested silicon as far as Altera is concerned, and anyone rebuilding this design
 * needs the same interposer.
 *
 * The block's global id and the symbol to intercept were originally identified by Ruurd Keizer,
 * https://github.com/ruurdk/sv_second_pcie_hip. This is an independent implementation of the
 * mechanism described there.
 *
 * Build:  gcc -shared -fPIC -O2 -o sv_pcie_hip_enable.so sv_pcie_hip_enable.c -ldl
 * Use:    LD_PRELOAD=/path/to/sv_pcie_hip_enable.so <quartus command>
 *         (bcrypt_storey_peak.py compiles and preloads this for you)
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

/* Mangled name of DEV_DIE_INFO::is_global_id_enabled(unsigned int) const. */
#define SYMBOL "_ZNK12DEV_DIE_INFO20is_global_id_enabledEj"

/* The PCIe hard IP block serving connector 0 on 5SGSMD5K1F40C1. */
#define HIDDEN_PCIE_HIP_GLOBAL_ID 1174964u

typedef bool (*is_enabled_fn)(const void *self, unsigned id);

static is_enabled_fn real_is_enabled;

/*
 * Resolved lazily rather than in a constructor: the preload is inherited by every child Quartus
 * spawns, and most of them never load libddb_dev.so at all. Failing at startup would break those.
 */
static bool resolve(void)
{
    void *lib;

    if (real_is_enabled != NULL)
        return true;

    /* Already mapped in the tools that care; RTLD_NOLOAD keeps us from pulling in a second copy. */
    lib = dlopen("libddb_dev.so", RTLD_LAZY | RTLD_LOCAL | RTLD_NOLOAD);
    if (lib == NULL)
        lib = dlopen("libddb_dev.so", RTLD_LAZY | RTLD_LOCAL);
    if (lib == NULL) {
        fprintf(stderr, "sv_pcie_hip_enable: cannot open libddb_dev.so: %s\n", dlerror());
        return false;
    }

    real_is_enabled = (is_enabled_fn)dlsym(lib, SYMBOL);
    if (real_is_enabled == NULL) {
        fprintf(stderr, "sv_pcie_hip_enable: cannot resolve %s: %s\n"
                        "  The symbol may have been renamed in this Quartus version.\n",
                SYMBOL, dlerror());
        return false;
    }
    return true;
}

bool _ZNK12DEV_DIE_INFO20is_global_id_enabledEj(const void *self, unsigned id)
{
    if (id == HIDDEN_PCIE_HIP_GLOBAL_ID)
        return true;

    if (!resolve()) {
        /*
         * Reporting "enabled" for blocks we cannot vet would silently corrupt placement, so refuse
         * loudly instead of guessing.
         */
        fprintf(stderr, "sv_pcie_hip_enable: refusing to answer for global id %u\n", id);
        abort();
    }
    return real_is_enabled(self, id);
}
