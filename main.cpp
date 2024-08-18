#include <iostream>
#include <iomanip>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

// Callback function called by pcap for every captured packet
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
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