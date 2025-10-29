#!/usr/bin/env python3
#
# This file is part of LiteX-Bcrypt.
#
# bcrypt_resources.py — Resource Usage Sweep Demonstrates Bcrypt scaling on Acorn CLE-215+.
#
# High-level:
# - Builds multiple configurations (proxies × cores_per_proxy).
# - Extracts LUT/FF/BRAM/DSP from Vivado utilization report.
# - Saves results in JSON and prints a clean table.
#
import os
import subprocess
import re
import json
from datetime import datetime

# Configurations to test ---------------------------------------------------------------------------

configs = [
    # (num_proxies, cores_per_proxy)
    (1, 1),
    (1, 2),
    (1, 4),
    (1, 8),
    (2, 8),
    (4, 8),
    (8, 8),
    (8, 16),
]

# Build & parse helpers ----------------------------------------------------------------------------

def run_build(num_proxies, cores_per_proxy):
    """Build design and return resource usage."""
    build_name = f"bcrypt_p{num_proxies}_c{cores_per_proxy}"
    build_dir = os.path.join("build", build_name)

    print(f"\n{'='*70}")
    print(f"BUILDING: {build_name} ({num_proxies} proxies × {cores_per_proxy} cores = {num_proxies*cores_per_proxy} total)")
    print(f"{'='*70}")

    cmd = [
        "./bcrypt_acorn.py",
        "--num-proxies", str(num_proxies),
        "--cores-per-proxy", str(cores_per_proxy),
        "--build"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print("Build failed.")
        return None

    # Find utilization report
    rpt_path = os.path.join(build_dir, "gateware", f"{build_name}_utilization_place.rpt")
    if not os.path.exists(rpt_path):
        print(f"Report not found: {rpt_path}")
        return None

    with open(rpt_path) as f:
        content = f.read()

    # Parse metrics
    lut  = re.search(r"Slice LUTs\s*\|\s*(\d+)", content)
    ff   = re.search(r"Slice Registers\s*\|\s*(\d+)", content)
    bram = re.search(r"Block RAM Tile\s*\|\s*(\d+)", content)
    dsp  = re.search(r"DSPs?\s*\|\s*(\d+)", content)

    return {
        "proxies"         : num_proxies,
        "cores_per_proxy" : cores_per_proxy,
        "total_cores"     : num_proxies * cores_per_proxy,
        "lut"             : int(lut.group(1))  if lut  else 0,
        "ff"              : int(ff.group(1))   if ff   else 0,
        "bram"            : int(bram.group(1)) if bram else 0,
        "dsp"             : int(dsp.group(1))  if dsp  else 0,
    }

# Main ---------------------------------------------------------------------------------------------
def main():
    results = []
    for p, c in configs:
        res = run_build(p, c)
        if res:
            results.append(res)
        else:
            print(f"Stopping sweep at {p}×{c}")
            break

    # Save JSON
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = f"resources_{timestamp}.json"
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved: {json_path}")

    # Print table
    print("\n" + "="*90)
    print("LITEX BCRYPT RESOURCE USAGE (Artix-7, 125 MHz)")
    print("="*90)
    print(f"{'Cores':>6} {'Proxies':>8} {'LUT':>10} {'FF':>10} {'BRAM':>6} {'DSP':>5}")
    print("-"*90)
    for r in results:
        print(f"{r['total_cores']:>6} {r['proxies']:>8} {r['lut']:>10,} {r['ff']:>10,} {r['bram']:>6} {r['dsp']:>5}")
    print("-"*90)
    if results:
        max_cores = results[-1]['total_cores']
        print(f"Max tested: {max_cores} cores → {results[-1]['lut']:,} LUTs")

if __name__ == "__main__":
    main()
