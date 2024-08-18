# Console-Network-Traffic-Analyzer


# Network Traffic Analyzer

## Overview

This project is a **Work in Progress** network traffic analyzer written in C++. The tool is designed to capture and analyze network traffic on specified network interfaces, with options for filtering, logging, and duration-based capture.

## Features

- **Packet Capture**: Capture packets from a specified network device.
- **Filtering**: Apply BPF (Berkeley Packet Filter) expressions to capture specific types of traffic.
- **Logging**: Save captured packets to a PCAP file for later analysis.
- **Duration-based Capture**: Capture packets for a specified duration.
- **Device Listing**: List available network devices to select from.
- **Cross-platform**: Compatible with Linux-based systems.

## Requirements

- **Operating System**: Linux or any POSIX-compliant system
- **Compiler**: GCC or Clang
- **Libraries**:
  - `libpcap`: Packet capture library

### Installation

To compile and run the project, ensure that you have the necessary dependencies installed.

#### Step 1: Install Dependencies

```bash
sudo apt-get update
sudo apt-get install libpcap-dev g++ make
```
#### Step 2: Clone the Repository
```bash
git clone https://github.com/yourusername/network-traffic-analyzer.git
cd network-traffic-analyzer
```
#### Step 3: Compile the Project
```bash
g++ -o analyzer main.cpp -lpcap -pthread
```
### Usage
The tool supports several command-line options to control its behavior.
```bash
./analyzer [-d device] [-n number] [-f filter] [-w filename] [-t seconds] [-h]
```
- -d [device]: Specify the network device to capture packets on.

- -n [number]: Specify the number of packets to capture. Set to -1 for indefinite capture.

- -f [filter]: Apply a BPF filter (e.g., "tcp port 80").

- -w [filename]: Write captured packets to a PCAP file.

- -t [seconds]: Capture packets for a specified duration, will nullify the -n argument(for now).
