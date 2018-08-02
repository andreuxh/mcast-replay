#include <pcap/pcap.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>


struct vlan_tag
{
    u_int16_t vlan_id;
    u_int16_t ether_type;
};


static pcap_t *pcap;

void handler(u_char *stop,
             const struct pcap_pkthdr * pkt_header, const u_char *pkt_data)
{
    static size_t pkt_count;
    pkt_count++;

    {
    if (pkt_header->caplen < pkt_header->len)
    {
        fprintf(stderr, "Short capture length [%u<%u]\n",
                        pkt_header->caplen, pkt_header->len);
        goto ret;
    }

    auto *p = pkt_data;
    auto *endp = p + pkt_header->len;
    auto *eth = reinterpret_cast<const ether_header*>(p);
    if ((p += sizeof(ether_header)) > endp)
    {
        fprintf(stderr, "Truncated Ethernet header [%u<%zu]\n",
                        pkt_header->len, p - pkt_data);
        goto ret;
    }

    auto ether_type = eth->ether_type;
    while (ether_type == htons(ETHERTYPE_VLAN))
    {
        auto *tag = reinterpret_cast<const vlan_tag*>(p);
        if ((p += sizeof(vlan_tag)) > endp)
        {
            fprintf(stderr, "Truncated VLAN tag [%u<%zu]\n",
                            pkt_header->len, p - pkt_data);
            goto ret;
        }
        ether_type = tag->ether_type;
    }
    if (ether_type != htons(ETHERTYPE_IP)) return;

    auto *iph = reinterpret_cast<const iphdr*>(p);
    auto iph_len = iph->ihl * 4u;
    if (iph_len < sizeof(iphdr))
    {
        fprintf(stderr, "Malformed IP header [ihl=%u]\n", iph->ihl);
        goto ret;
    }
    if ((p += iph_len) > endp)
    {
        fprintf(stderr, "Truncated IP header [%u<%zu]\n",
                        pkt_header->len, p - pkt_data);
        goto ret;
    }

    if (iph->protocol != IPPROTO_UDP) return;
    if (!IN_MULTICAST(ntohl(iph->daddr))) return;

    auto *udph = reinterpret_cast<const udphdr*>(p);
    if ((p += sizeof(udphdr)) > endp)
    {
        fprintf(stderr, "Truncated UDP header [%u<%zu]\n",
                        pkt_header->len, p - pkt_data);
        goto ret;
    }

    auto len = ntohs(udph->len) - sizeof(udphdr);
    if (p + len > endp)
    {
        fprintf(stderr, "Truncated UDP payload [%u<%zu]\n",
                        pkt_header->len, p + len - pkt_data);
        goto ret;
    }

    auto sec = pkt_header->ts.tv_sec;
    auto saddr = ntohl(iph->saddr);
    auto daddr = ntohl(iph->daddr);
    printf("%02ld:%02ld:%02ld.%06ld IP "
           "%hhu.%hhu.%hhu.%hhu.%u > %hhu.%hhu.%hhu.%hhu.%u\n",
           sec / 3600 % 24, sec / 60 % 60, sec % 60, pkt_header->ts.tv_usec,
           saddr >> 24, saddr >> 16, saddr >> 8, saddr, ntohs(udph->source),
           daddr >> 24, daddr >> 16, daddr >> 8, daddr, ntohs(udph->dest));
    }
    return;

ret:
    if (stop)
    {
        pcap_breakloop(pcap);
    }
}

#define PCAP_DIE(pcap, prefix) do { \
    pcap_perror(pcap, const_cast<char*>(prefix)); \
    return -1; \
} while (0)

int main(int argc, char *argv[])
{
    if (argc < 2) return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap = pcap_open_offline(argv[1], errbuf);
    if (!pcap)
    {
        fprintf(stderr, "Could not open %s: %s\n", argv[1], errbuf);
        return 1;
    }

    if (argc > 2)
    {
        struct bpf_program bpf;
        if (pcap_compile(pcap, &bpf, argv[2], 1, PCAP_NETMASK_UNKNOWN) < 0)
        {
            PCAP_DIE(pcap, "pcap_compile");
        }

        if (pcap_setfilter(pcap, &bpf) < 0)
        {
            PCAP_DIE(pcap, "pcap_setfilter");
        }
    }

    if (pcap_loop(pcap, -1, handler, 0) < 0)
    {
        PCAP_DIE(pcap, "pcap_loop");
    }

    return 0;
}
