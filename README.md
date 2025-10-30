                         __   _ __      _  __  ___                    __
                        / /  (_) /____ | |/_/ / _ )__________ _____  / /_
                       / /__/ / __/ -_)>  <  / _  / __/ __/ // / _ \/ __/
                      /____/_/\__/\__/_/|_| /____/\__/_/  \_, / .__/\__/
                                                         /___/_/
                                  LiteX-Bcrypt Proof of Concept

[> Intro
--------
The project provides a LiteX-based infrastructure for integrating a Bcrypt cryptographic accelerator into FPGA designs.

![](doc/litex_bcrypt_poc_architecture.png)

The design includes a LiteX SoC with peripherals (SRAM, CSRs, etc.) and adds AXI8Streamer, AXI8Recorder, and the BcryptWrapper for input/output streaming.

A simple test script is provided to stream packets through the core and capture results. The hardware target is the Acorn CLE-215+ with PCIe, but the PoC is also simulatable.

The project originated from a request to port existing Bcrypt cores from ZTEX boards to modern FPGAs using LiteX for flexible acceleration over PCIe/Ethernet.

[> Prerequisites / System setup
-------------------------------

These are required to build and use the FPGA design and associated software:
- Linux (Ubuntu 20.04 tested)
- Python 3
- Xilinx Vivado (for synthesis)
- Acorn CLE-215+ board
- USB cable (JTAG)
- OpenFPGALoader

[> Installing LiteX
-------------------
The LiteX framework provides a convenient and efficient infrastructure to create FPGA Cores/SoCs, to explore various digital design architectures and create full FPGA based systems.

In this project, LiteX is used to generate the FPGA design and to provide the cores of the design.

To install LiteX, the following steps can be followed:
1. Download the LiteX installation script with the following command:
```sh
$ wget https://raw.githubusercontent.com/enjoy-digital/litex/master/litex_setup.py
```
2. Make the script executable with the following command:
```sh
$ chmod +x litex_setup.py
```
3. Run the script with the `--init` and `--install` arguments to initialize and install LiteX, respectively:
```sh
$ sudo ./litex_setup.py --init --install
```
For more detailed instructions and additional information, please see the LiteX installation guide at https://github.com/enjoy-digital/litex/wiki/Installation.

[> Installing OpenFPGALoader
-----------------------------
OpenFPGALoader is a free and open-source tool that can be used to load FPGA bitstreams or flash them.

To install OpenFPGALoader on your system:
```sh
apt-get install libftdi1-2 libftdi1-dev libhidapi-hidraw0 libhidapi-dev libudev-dev cmake pkg-config make g++
git clone https://github.com/trabucayre/openFPGALoader
cd openFPGALoader
mkdir build
cd build
cmake ../
make
sudo make install
```
For more detailed instructions and additional information, please see the OpenFPGALoader project at https://github.com/trabucayre/openFPGALoader.

[> Build and Flash the FPGA design
----------------------------------

![](doc/litex_bcrypt_poc_hardware_setup.png)

```sh
# Build and flash (M.2 slot, x4 lanes)
./bcrypt_acorn.py --variant=m2 --build --flash

# Or: baseboard (x1 lane)
./bcrypt_acorn.py --variant=baseboard --build --flash
```

> **Note**: Use `--variant=m2` (default) or `--variant=baseboard`.

[> Test the Hardware over PCIe
-------------------------------
### 1. Build & Load LitePCIe Driver
```sh
cd software/kernel
make clean all
sudo insmod litepcie.ko
```

### 2. Rescan PCIe Bus
```sh
cd ../../software
./rescan.py
```

### 3. Verify Device
```sh
lspci -d 10ee: -v
```
**Expected output**:
```
04:00.0 Processor [0b80]: Xilinx Corporation Device 7021
    Subsystem: Xilinx Corporation Device 0007
    Flags: bus master, fast devsel, latency 0, IRQ 105, IOMMU group 22
    Memory at fc800000 (32-bit, non-prefetchable) [size=1M]
    Capabilities: <access denied>
    Kernel driver in use: litepcie

```

### 4. Start LiteX Server (PCIe)
```sh
litex_server --pcie --pcie-bar=04:00.0
```
> Replace `04:00.0` with your BAR from `lspci`.

### 5. Run Test (in another terminal)
```sh
./test_bcrypt.py
```

**Success looks like**:
```
Starting recorder (captures until last packet)...
Writing 46 bytes into streamer_mem @ 0x00040000...
  → streamer done
Writing 23 bytes into streamer_mem @ 0x00040000...
  → streamer done
Writing 24 bytes into streamer_mem @ 0x00040000...
  → streamer done
Recorder captured 22 bytes.
First 64 captured bytes:
02 d2 b9 35 04 00 00 00 03 00 f6 2d 46 ca 01 00 00 00 fe ff ff ff
app_status=0x00 pkt_comm_status=0x00
Test complete.
```

[> Build and Run Simulation
----------------------------
A simulation of the FPGA design is provided and can also be run and configured dynamically.
```sh
./bcrypt_sim.py
litex_server --udp
./test_bcrypt.py
```

[> Resource Usage
-----------------

![](doc/litex_bcrypt_poc_floorplan.png)

Run sweep:
```sh
./bcrypt_resources.py
```

| Cores | Proxies | LUTs   | FFs    | BRAM | DSP |
|-------|---------|--------|--------|------|-----|
| 1     | 1       | 8,243  | 6,773  |   47 | 1   |
| 2     | 1       | 8,668  | 7,008  |   49 | 1   |
| 4     | 1       | 9,505  | 7,477  |   53 | 1   |
| 8     | 1       | 11,193 | 8,418  |   61 | 1   |
| 16    | 2       | 14,593 | 10,319 |   77 | 1   |
| 32    | 4       | 21,343 | 14,113 |  109 | 1   |
| 64    | 8       | 34,840 | 21,700 |  173 | 1   |
| 128   | 8       | 61,678 | 36,684 |  301 | 1   |
| **150** | **10** | **70,973** | **41,884** | **345** | **1** |

> **150 cores tested** (10 × 15) — **94.5% BRAM**

[> Comparison with ZTEX 1.15y (Spartan-6 LX150)
-----------------------------------------------
| Metric              | **LiteX (Artix-7)** | **ZTEX (Spartan-6)** |
|---------------------|---------------------|----------------------|
| **Cores per FPGA**  | **150**             | 124                  |
| **Cores per Board** | 150                 | **496 (4× FPGA)**    |
| **Clock**           | 125 MHz             | 141 MHz (152 MHz OC) |
| **Interface**       | PCIe Gen2 x4        | USB 2.0              |

[> Limitations with current PoC
---------------
- BRAM is limiting factor on XC7A200T (365 total).
- No DMA, only MMAP SRAM Writing/Reading for PoC.
- No IRQ, only polling for PoC.
- Very basic CMP_CONFIG/WORD_LIST/WORD_GEN, to validate infrastructure/integration, needs to be tested with realistic use-case.
- 125MHz Sys Clk, passing timing with 150 cores, max frequency still to evaluate.
