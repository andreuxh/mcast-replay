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


class udp_replayer
{
public:
    udp_replayer()
    {}
    udp_replayer(const char *filename)
      : filename_{filename} 
    {
        open();
    }

    ~udp_replayer()
    {
        close();
    }

    bool open(const char *filename)
    {
        close();
        filename_ = filename;
        return open();
    }

    void close()
    {
        if (pcap_)
        {
            pcap_close(pcap_);
            pcap_ = nullptr;
            filename_ = nullptr;
        }
    }

    int loop(int count = -1)
    {
        return pcap_loop(pcap_, count, &call_handler,
                         reinterpret_cast<u_char*>(this));
    }
    void handle(const struct pcap_pkthdr *pkt_header,
                const u_char *pkt_data);

    pcap_t *pcap() { return pcap_; }

    bool fail() const { return filename_ && !pcap_; }
    const char *error() const
    {
        if (!filename_) return nullptr;
        else if (!pcap_) return errbuf_;
        else return pcap_geterr(pcap_);
    }

private:
    bool open()
    {
        pcap_ = pcap_open_offline(filename_, errbuf_);
        return pcap_;
    }

    static void call_handler(u_char *self,
                             const struct pcap_pkthdr *pkt_header,
                             const u_char *pkt_data)
    {
        reinterpret_cast<udp_replayer*>(self)->handle(pkt_header, pkt_data);
    }

    pcap_t *pcap_ = nullptr;
    const char *filename_ = nullptr;
    bool stop_on_error_ = false;
    char errbuf_[PCAP_ERRBUF_SIZE];
};


void udp_replayer::handle(const struct pcap_pkthdr *pkt_header,
                          const u_char *pkt_data)
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
    if (stop_on_error_)
    {
        pcap_breakloop(pcap_);
    }
}

#define REPLAYER_DIE(rpl, prefix) do { \
    fprintf(stderr, "%s: %s\n", prefix, rpl.error()); \
    return -1; \
} while (0)

int main(int argc, char *argv[])
{
    if (argc < 2) return -1;

    udp_replayer rpl(argv[1]);
    if (rpl.fail())
    {
        fprintf(stderr, "Could not open %s: %s\n", argv[1], rpl.error());
        return 1;
    }

    if (argc > 2)
    {
        auto *pcap = rpl.pcap();
        struct bpf_program bpf;
        if (pcap_compile(pcap, &bpf, argv[2], 1, PCAP_NETMASK_UNKNOWN) < 0
            || pcap_setfilter(pcap, &bpf) < 0)
        {
            REPLAYER_DIE(rpl, "pcap_compile/setfilter");
        }
    }

    if (rpl.loop() < 0)
    {
        REPLAYER_DIE(rpl, "pcap_loop");
    }

    return 0;
}
