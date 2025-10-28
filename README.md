           __   _ __      _  __  ___                    __ 
          / /  (_) /____ | |/_/ / _ )__________ _____  / /_
         / /__/ / __/ -_)>  <  / _  / __/ __/ // / _ \/ __/
        /____/_/\__/\__/_/|_| /____/\__/_/  \_, / .__/\__/ 
                                           /___/_/         
                    LiteX-Bcrypt Proof of Concept

[> Intro
--------
The project provides a LiteX-based infrastructure for integrating a Bcrypt cryptographic accelerator into FPGA designs.

The design includes a LiteX SoC with peripherals (SRAM, CSRs, etc.) and adds AXI8Streamer, AXI8Recorder, and the BcryptWrapper for input/output streaming.

A simple test script is provided to stream packets through the core and capture results. The hardware target is the Acorn CLE-215+ with PCIe, but the PoC is also simulatable.

The project originated from a request to port existing Bcrypt cores from ZTEX boards to modern FPGAs using LiteX for flexible acceleration over PCIe/Ethernet.

[> Prerequisites / System setup
-------------------------------

These are required to build and use the FPGA design and associated software:
- Linux computer (Tested on Ubuntu 20.04).
- Python3, Xilinx Vivado (for hardware target).
- Acorn CLE-215+ board (for hardware target).
- USB cable for JTAG.
- OpenFPGALoader for loading/flashing.

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
![](doc/acorn.jpg)
Build the hardware target with:
```sh
./bcrypt_acorn.py --build --load
```
Or flash it with:
```sh
./bcrypt_acorn.py --build --flash
```
[> Test the hardware over LitePCIe driver
------------------------------------------
Install the LitePCIe driver and use the test script:
```sh
generate_litepcie_software(soc, "software/driver")
cd software/driver
make
sudo ./litepcie_test
./test_bcrypt.py
```

[> Build and Run simulation
----------------------------
A simulation of the FPGA design is provided and can also be run and configured dynamically.
```sh
./bcrypt_sim.py
litex_server --udp
./test_bcrypt.py
```

[> Resource usage
-----------------
TODO.

[> Limitations with current PoC
-------------------------------
TODO.
