/*
  Copyright (c) 2018 Hugues Andreux
  
  Permission is hereby granted, free of charge, to any person obtaining a
  copy of this software and associated documentation files (the "Software"),
  to deal in the Software without restriction, including without limitation
  the rights to use, copy, modify, merge, publish, distribute, sublicense,
  and/or sell copies of the Software, and to permit persons to whom the
  Software is furnished to do so, subject to the following conditions:
  
  The above copyright notice and this permission notice shall be included
  in all copies or substantial portions of the Software.
  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
  OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
  ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
  OTHER DEALINGS IN THE SOFTWARE.
*/

#include <pcap/pcap.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <errno.h>
#include <fenv.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <limits>
#include <string>
#include <stdexcept>

#include <assert.h>

struct vlan_tag
{
    u_int16_t vlan_id;
    u_int16_t ether_type;
};


class udp_replayer
{
public:
    udp_replayer(const char *filename = nullptr)
      : filename_{filename}, socket_{socket(AF_INET, SOCK_DGRAM, 0)}
    {
        if (socket_ == -1)
        {
            std::string errstr = "Can't create socket: ";
            errstr += strerror(errno); // NB: not MT-safe!
            throw std::runtime_error(errstr);
        }

        dest_.sin_family = AF_INET;
        if (filename_)
        {
            open();
        }
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
    bool handle(const pcap_pkthdr *pkt_header, const u_char *pkt_data);

    pcap_t *pcap() { return pcap_; }

    bool fail() const { return filename_ && !pcap_; }
    const char *error() const
    {
        if (!filename_) return nullptr;
        else if (!pcap_) return errbuf_;
        else return pcap_geterr(pcap_);
    }

    void replay_min_time_interval(double min_time_interval)
    {
        time_interval_from_double(min_time_interval_, min_time_interval);
        check_time_intervals();
    }
    void replay_max_time_interval(double max_time_interval)
    {
        time_interval_from_double(max_time_interval_, max_time_interval);
        check_time_intervals();
    }

    void multicast_filter(bool allow_multicast, bool allow_unicast)
    {
        mcast_filter_ = !allow_multicast << 0
                      | !allow_unicast   << 1;
    }

    void dry_run(bool value)            { dry_run_ = value; }
    void stop_on_error(bool value)      { stop_on_error_ = value; }

private:
    bool open()
    {
        pcap_ = pcap_open_offline(filename_, errbuf_);
        return pcap_;
    }

    static void call_handler(u_char *rpl, const pcap_pkthdr *pkt_header,
                                          const u_char *pkt_data)
    {
        auto& self = *reinterpret_cast<udp_replayer*>(rpl);
        if (!self.handle(pkt_header, pkt_data) && self.stop_on_error_)
        {
            pcap_breakloop(self.pcap_);
        }
    }

    bool replay_datagram(const pcap_pkthdr *pkt_header,
                         const iphdr *iph, const udphdr *udph);
    bool print_datagram(const pcap_pkthdr *pkt_header,
                        const iphdr *iph, const udphdr *udph);

    static void time_interval_from_double(timeval& tv, double t);
    static void clock_normalize(timespec *ts);

    void check_time_intervals()
    {
        if (timercmp(&min_time_interval_, &max_time_interval_, >))
        {
            throw std::domain_error("Minimum interval cannot exceed "
                                    "maximum interval");
        }
    }

    static void error(const char *msg, size_t got, size_t expected)
    {
        fprintf(stderr, "%s [%zu<%zu]\n", msg, got, expected);
    }

    enum time_unit_ratio
    {
        us_per_sec =    1000000,
        ns_per_sec = 1000000000,
    };

    enum mcast_mask
    {
        drop_multicast = 1 << 0,
        drop_unicast   = 1 << 1,
    };

    pcap_t *pcap_ = nullptr;
    const char *filename_ = nullptr;
    timeval pcap_timestamp_    = { -1, -1 };
    timeval min_time_interval_ = {  0,  0 };
    timeval max_time_interval_ = { std::numeric_limits<time_t>::max(),
                                   us_per_sec - 1                    };
    timespec replay_timestamp_ = { -1, -1 };
    size_t pkt_count = 0;
    unsigned mcast_filter_ = drop_unicast;
    int socket_;
    sockaddr_in dest_;
    bool dry_run_ = false;
    bool stop_on_error_ = false;
    char errbuf_[PCAP_ERRBUF_SIZE];
};


bool udp_replayer::handle(const pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
    pkt_count++;

    if (pkt_header->caplen < pkt_header->len)
    {
        error("Short capture length", pkt_header->caplen, pkt_header->len);
        return false;
    }

    auto *p = pkt_data;
    auto *endp = p + pkt_header->len;
    auto *eth = reinterpret_cast<const ether_header*>(p);
    if ((p += sizeof(ether_header)) > endp)
    {
        error("Truncated Ethernet header", pkt_header->len, p - pkt_data);
        return false;
    }

    auto ether_type = eth->ether_type;
    while (ether_type == htons(ETHERTYPE_VLAN))
    {
        auto *tag = reinterpret_cast<const vlan_tag*>(p);
        if ((p += sizeof(vlan_tag)) > endp)
        {
            error("Truncated VLAN tag", pkt_header->len, p - pkt_data);
            return false;
        }
        ether_type = tag->ether_type;
    }
    if (ether_type != htons(ETHERTYPE_IP)) return true;

    auto *iph = reinterpret_cast<const iphdr*>(p);
    auto iph_len = iph->ihl * 4u;
    if (iph_len < sizeof(iphdr))
    {
        fprintf(stderr, "Malformed IP header [ihl=%u]\n", iph->ihl);
        return false;
    }
    if ((p += iph_len) > endp)
    {
        error("Truncated IP header", pkt_header->len, p - pkt_data);
        return false;
    }

    if ((1 << !IN_MULTICAST(ntohl(iph->daddr))) & mcast_filter_) return true;

    if (iph->protocol != IPPROTO_UDP) return true;

    auto *udph = reinterpret_cast<const udphdr*>(p);
    if ((p += sizeof(udphdr)) > endp)
    {
        error("Truncated UDP header", pkt_header->len, p - pkt_data);
        return false;
    }

    auto len = ntohs(udph->len) - sizeof(udphdr);
    if (p + len > endp)
    {
        error("Truncated UDP payload", pkt_header->len, p + len - pkt_data);
        return false;
    }

    if (!dry_run_)
    {
        return replay_datagram(pkt_header, iph, udph);
    }
    else
    {
        return print_datagram(pkt_header, iph, udph);
    }
}

void udp_replayer::time_interval_from_double(timeval& tv, double t)
{
    if (signbit(t))
    {
        throw std::domain_error("Time interval cannot be negative");
    }

    feclearexcept(FE_ALL_EXCEPT);
    #ifndef NDEBUG
    errno = 0;
    #endif

    double ti, tf = modf(t, &ti);     // modf: always defined, no errors occur.
    long us = lrint(tf * us_per_sec); // lrint: can raise FE_INVALID,
    time_t sec = lrint(ti);           //        do not set errno

    assert(!errno && !fetestexcept(FE_DIVBYZERO|FE_OVERFLOW|FE_UNDERFLOW));
    if (fetestexcept(FE_INVALID))
    {
        throw std::domain_error("Time interval cannot be this large: "
                                + std::to_string(t));
    }

    if (us >= us_per_sec)
    {
        assert(us == us_per_sec);
        ++sec;
        us = 0;
    }
    tv.tv_sec = sec;
    tv.tv_usec = us;
}

inline void udp_replayer::clock_normalize(timespec *ts)
{
    ts->tv_sec  += ts->tv_nsec / ns_per_sec;
    ts->tv_nsec %= ns_per_sec;
    if (ts->tv_nsec < 0)
    {
        --ts->tv_sec;
        ts->tv_nsec += ns_per_sec;
    }
}

bool udp_replayer::replay_datagram(const pcap_pkthdr *pkt_header,
                                   const iphdr *iph, const udphdr *udph)
{
    if (replay_timestamp_.tv_nsec < 0)
    {
        clock_gettime(CLOCK_MONOTONIC, &replay_timestamp_);
    }
    else
    {
        timeval itv;
        timersub(&(pkt_header->ts), &pcap_timestamp_, &itv);
        if (timercmp(&itv, &min_time_interval_, <))
        {
            memcpy(&itv, &min_time_interval_, sizeof(timeval));
        }
        else if (timercmp(&itv, &max_time_interval_, >))
        {
            memcpy(&itv, &max_time_interval_, sizeof(timeval));
        }

        replay_timestamp_.tv_sec  += itv.tv_sec;
        replay_timestamp_.tv_nsec += itv.tv_usec * 1000;
        clock_normalize(&replay_timestamp_);

        while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME,
                               &replay_timestamp_, nullptr) == -1
               && errno == EINTR) {}
    }
    memcpy(&pcap_timestamp_, &pkt_header->ts, sizeof(timeval));

    dest_.sin_addr.s_addr = iph->daddr;
    dest_.sin_port = udph->dest;
    auto buf = reinterpret_cast<const char*>(udph) + sizeof(udphdr);
    auto len = udph->len - sizeof(udphdr);
    return -1 != sendto(socket_, buf, len, 0,
                        reinterpret_cast<sockaddr*>(&dest_), sizeof(dest_));
}

bool udp_replayer::print_datagram(const pcap_pkthdr *pkt_header,
                                  const iphdr *iph, const udphdr *udph)
{
    auto sec = pkt_header->ts.tv_sec;
    auto saddr = ntohl(iph->saddr);
    auto daddr = ntohl(iph->daddr);
    printf("%02ld:%02ld:%02ld.%06ld IP "
           "%hhu.%hhu.%hhu.%hhu.%u > %hhu.%hhu.%hhu.%hhu.%u\n",
           sec / 3600 % 24, sec / 60 % 60, sec % 60, pkt_header->ts.tv_usec,
           saddr >> 24, saddr >> 16, saddr >> 8, saddr, ntohs(udph->source),
           daddr >> 24, daddr >> 16, daddr >> 8, daddr, ntohs(udph->dest));

    return true;
}


#define REPLAYER_DIE(rpl, prefix) do { \
    fprintf(stderr, "%s: %s\n", prefix, rpl.error()); \
    return -1; \
} while (0)

int mcast_replay(int argc, char *argv[])
{
    udp_replayer rpl;

    int opt;
    const char *filter = nullptr;

    while ((opt = getopt(argc, argv, "f:m:M:nSu::")) != -1)
    {
        switch (opt)
        {
        case 'f':
            filter = optarg;
            break;
        case 'm':
            rpl.replay_min_time_interval(atof(optarg));
            break;
        case 'M':
            rpl.replay_max_time_interval(atof(optarg));
            break;
        case 'n':
            rpl.dry_run(true);
            break;
        case 'S':
            rpl.stop_on_error(true);
            break;
        case 'u':
            {
                bool allow_unicast = true;
                bool allow_multicast = (optarg && *optarg == 'm');
                rpl.multicast_filter(allow_multicast, allow_unicast);
            }
            break;
        }
    }

    const char *filename = (optind < argc) ? argv[optind] : "-";
    if (!rpl.open(filename))
    {
        fprintf(stderr, "Could not open %s: %s\n", argv[1], rpl.error());
        return EXIT_FAILURE;
    }

    if (filter)
    {
        auto *pcap = rpl.pcap();
        bpf_program bpf;
        if (pcap_compile(pcap, &bpf, filter, 1, PCAP_NETMASK_UNKNOWN) < 0 ||
            pcap_setfilter(pcap, &bpf) < 0)
        {
            REPLAYER_DIE(rpl, "pcap_compile/setfilter");
        }
    }

    if (rpl.loop() < 0)
    {
        REPLAYER_DIE(rpl, "pcap_loop");
    }

    return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
    try
    {
        return mcast_replay(argc, argv);
    }
    catch (const std::exception& ex)
    {
        fprintf(stderr, "mcast-replay: %s\n", ex.what());
        return EXIT_FAILURE;
    }
}
