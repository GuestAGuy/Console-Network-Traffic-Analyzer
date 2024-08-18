#include <iostream>
#include <pcap.h>

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    std::cout << "Packet captured with length: " << pkthdr->len << std::endl;
}

int main() {
    pcap_if_t *alldevs, *device;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    device = alldevs; // Just pick the first device for simplicity

    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device: " << errbuf << std::endl;
        return 2;
    }

    pcap_loop(handle, 10, packetHandler, nullptr);

    pcap_freealldevs(alldevs);
    pcap_close(handle);
    return 0;
}