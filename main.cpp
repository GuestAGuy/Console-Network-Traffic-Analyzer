#include <iostream>
#include <iomanip>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <atomic>
#include <thread>
#include <mutex>

std::atomic<bool> keep_running(true); // Atomic flag for thread safety
std::mutex pcap_mutex; // Mutex to protect access to the pcap handle

// Function to print usage information
void print_usage() {
    std::cout << "Usage: ./analyzer [-d device] [-n number] [-f filter] [-w filename] [-t seconds] [-h]\n";
    std::cout << "  -d [device]  : Specify the network device to capture packets on.\n";
    std::cout << "  -n [number]  : Specify the number of packets to capture.\n";
    std::cout << "  -f [filter]  : Apply a BPF filter to capture specific traffic (e.g., 'tcp port 80').\n";
    std::cout << "  -w [filename]: Write captured packets to a file (PCAP format).\n";
    std::cout << "  -t [seconds] : Capture packets for a specified duration (in seconds), will nullify -n number, for now.\n";
    std::cout << "  -h           : Display this help message.\n";
}

// Function to list all available network devices
void list_devices() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return;
    }

    std::cout << "Available devices:\n";
    for (device = alldevs; device; device = device->next) {
        std::cout << "  " << device->name;
        if (device->description) {
            std::cout << " (" << device->description << ")";
        }
        std::cout << std::endl;
    }

    pcap_freealldevs(alldevs);
}

// Timer function to stop capturing after a duration
void capture_timer(int seconds, pcap_t *handle) {
    sleep(seconds);
    keep_running = false;
    
    // Ensure thread-safe access to the pcap handle
    std::lock_guard<std::mutex> lock(pcap_mutex);
    if (handle) {
        pcap_breakloop(handle);
    }
}

// Callback function called by pcap for every captured packet
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    if(!keep_running) {
        pcap_breakloop(reinterpret_cast<pcap_t*>(userData));
        return;
    }

    // Parse Ethernet header
    struct ether_header *ethHeader;
    ethHeader = (struct ether_header*)packet;

    if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
        // IPv4 packet
        const struct ip* ipHeader;
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));

        char srcIp[INET_ADDRSTRLEN];
        char dstIp[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &(ipHeader->ip_src), srcIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIp, INET_ADDRSTRLEN);

        std::cout << std::left << std::setw(15) << "IPv4 Packet"
                  << std::setw(15) << "Source IP: " << srcIp 
                  << " -> " << "Destination IP: " << dstIp << std::endl;

        // Determine protocol (TCP/UDP)
        if (ipHeader->ip_p == IPPROTO_TCP) {
            const struct tcphdr* tcpHeader;
            tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            std::cout << std::setw(15) << ""
                      << std::setw(15) << "Protocol: TCP"
                      << "Source Port: " << ntohs(tcpHeader->source)
                      << " -> Destination Port: " << ntohs(tcpHeader->dest) << std::endl;
        } else if (ipHeader->ip_p == IPPROTO_UDP) {
            const struct udphdr* udpHeader;
            udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            std::cout << std::setw(15) << ""
                      << std::setw(15) << "Protocol: UDP"
                      << "Source Port: " << ntohs(udpHeader->source)
                      << " -> Destination Port: " << ntohs(udpHeader->dest) << std::endl;
        } else {
            std::cout << std::setw(15) << ""
                      << std::setw(15) << "Protocol: Other" << std::endl;
        }

    } else if (ntohs(ethHeader->ether_type) == ETHERTYPE_IPV6) {
        // IPv6 packet
        const struct ip6_hdr* ip6Header;
        ip6Header = (struct ip6_hdr*)(packet + sizeof(struct ether_header));

        char srcIp[INET6_ADDRSTRLEN];
        char dstIp[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &(ip6Header->ip6_src), srcIp, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6Header->ip6_dst), dstIp, INET6_ADDRSTRLEN);

        std::cout << std::left << std::setw(15) << "IPv6 Packet"
                  << std::setw(15) << "Source IP: " << srcIp 
                  << " -> " << "Destination IP: " << dstIp << std::endl;

        // Determine protocol (TCP/UDP)
        if (ip6Header->ip6_nxt == IPPROTO_TCP) {
            const struct tcphdr* tcpHeader;
            tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            std::cout << std::setw(15) << ""
                      << std::setw(15) << "Protocol: TCP"
                      << "Source Port: " << ntohs(tcpHeader->source)
                      << " -> Destination Port: " << ntohs(tcpHeader->dest) << std::endl;
        } else if (ip6Header->ip6_nxt == IPPROTO_UDP) {
            const struct udphdr* udpHeader;
            udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            std::cout << std::setw(15) << ""
                      << std::setw(15) << "Protocol: UDP"
                      << "Source Port: " << ntohs(udpHeader->source)
                      << " -> Destination Port: " << ntohs(udpHeader->dest) << std::endl;
        } else {
            std::cout << std::setw(15) << ""
                      << std::setw(15) << "Protocol: Other" << std::endl;
        }

    } else {
        std::cout << std::setw(15) << "Non-IP packet"
                  << "Skipping..." << std::endl;
    }

    std::cout << std::endl;
}


int main(int argc, char *argv[]) {
    char *device = nullptr;
    int num_packets = 10;  // Default to capturing 10 packets if not specified
    char *filter_exp = nullptr;
    char *filename = nullptr;
    int capture_duration = 0;
    int opt;

    // If no arguments are provided, list all devices
    if (argc == 1) {
        list_devices();
        return 0;
    }

    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "d:n:f:w:t:h")) != -1) {
        switch (opt) {
            case 'd':
                device = optarg;
                break;
            case 'n':
                num_packets = std::stoi(optarg);
                break;
            case 'f':
                filter_exp = optarg;
                break;
            case 'w':
                filename = optarg;
                break;
            case 't':
                capture_duration = std::stoi(optarg);
                break;
            case 'h':
                print_usage();
                return 0;
            default:
                print_usage();
                return 1;
        }
    }

    // If no device is specified, print an error and exit
    if (device == nullptr) {
        std::cerr << "Error: Device must be specified using the -d option.\n";
        print_usage();
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net;

    // Open the specified device for packet capture
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device " << device << ": " << errbuf << std::endl;
        return 2;
    }

    // Apply the filter if specified
    if (filter_exp) {
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            std::cerr << "Error parsing filter: " << filter_exp << std::endl;
            pcap_close(handle);
            return 2;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Error setting filter: " << filter_exp << std::endl;
            pcap_close(handle);
            return 2;
        }
    }

    // Start the timer in a separate thread if duration is specified
    if (capture_duration > 0) {
        std::thread timer_thread(capture_timer, capture_duration, handle);
        timer_thread.detach(); // Detach the thread to let it run independently
        num_packets = -1;
    }

    // Write to file if specified
    if (filename) {
        pcap_dumper_t *dumper = pcap_dump_open(handle, filename);
        if (dumper == nullptr) {
            std::cerr << "Error opening file for writing: " << filename << std::endl;
            pcap_close(handle);
            return 2;
        }
        std::cout << "Writing packets to " << filename << "...\n";
        pcap_loop(handle, num_packets, [](u_char *dumper, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
            pcap_dump(dumper, pkthdr, packet);
        }, reinterpret_cast<u_char*>(dumper));
        pcap_dump_close(dumper);
    } else {
        // Default packet capture loop
        std::cout << "Listening on " << device << "...\n";
        pcap_loop(handle, num_packets, packetHandler, reinterpret_cast<u_char*>(handle));
    }

    std::lock_guard<std::mutex> lock(pcap_mutex);
    pcap_close(handle);
    return 0;
}