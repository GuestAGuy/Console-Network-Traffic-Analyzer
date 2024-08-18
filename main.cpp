#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

// Callback function called by pcap for every captured packet
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // Parse Ethernet header
    struct ether_header *ethHeader;
    ethHeader = (struct ether_header*)packet;

    // Check if IP packet (ETHERTYPE_IP)
    if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
        std::cout << "Ethernet: Source MAC: ";
        for(int i = 0; i < 6; i++) {
            std::cout << std::hex << (int)ethHeader->ether_shost[i];
            if (i < 5) std::cout << ":";
        }
        std::cout << " -> Destination MAC: ";
        for(int i = 0; i < 6; i++) {
            std::cout << std::hex << (int)ethHeader->ether_dhost[i];
            if (i < 5) std::cout << ":";
        }
        std::cout << std::dec << std::endl;

        // Parse IP header
        const struct ip* ipHeader;
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));

        char srcIp[INET_ADDRSTRLEN];
        char dstIp[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &(ipHeader->ip_src), srcIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIp, INET_ADDRSTRLEN);

        std::cout << "IP: Source IP: " << srcIp << " -> Destination IP: " << dstIp << std::endl;

        // Determine protocol (TCP/UDP)
        if (ipHeader->ip_p == IPPROTO_TCP) {
            const struct tcphdr* tcpHeader;
            tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            std::cout << "Protocol: TCP, Source Port: " << ntohs(tcpHeader->source)
                      << ", Destination Port: " << ntohs(tcpHeader->dest) << std::endl;
        } else if (ipHeader->ip_p == IPPROTO_UDP) {
            const struct udphdr* udpHeader;
            udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            std::cout << "Protocol: UDP, Source Port: " << ntohs(udpHeader->source)
                      << ", Destination Port: " << ntohs(udpHeader->dest) << std::endl;
        } else {
            std::cout << "Protocol: Other" << std::endl;
        }
    } else {
        std::cout << "Non-IP packet, skipping..." << std::endl;
    }

    std::cout << std::endl;
}

int main() {
    pcap_if_t *alldevs, *device;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Get all network interfaces
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    // Use the first available device
    device = alldevs;
    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr) {
        std::cerr << "Could not open device: " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return 2;
    }

    std::cout << "Listening on " << device->name << "..." << std::endl;

    // Start packet capture
    pcap_loop(handle, 10, packetHandler, nullptr);

    pcap_freealldevs(alldevs);
    pcap_close(handle);
    return 0;
}