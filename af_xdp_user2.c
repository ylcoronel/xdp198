#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/resource.h>

#include <bpf/bpf.h>
#include <bpf/xsk.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/ip.h>

#include <stdio.h>       //For standard things
#include <stdlib.h>      // malloc
#include <string.h>      //memset                                                                                                                                        
#include <netinet/ip_icmp.h>     //Provides declarations for icmp header
//#include<netinet/udp.h> //Provides declarations for udp header
#include <netinet/tcp.h> //Provides declarations for tcp header
//#include <netinet/ip.h>  //Provides declarations for ip header
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
# define NO_OF_CHARS 256

//static bool ProcessPacket(unsigned char* , int);
static bool process_udp_packet(unsigned char *Buffer , int Size);
void prefixSuffixArray(char* pat, int M, int* pps);
void check_pattern(unsigned char *data, int Size);
int max (int a, int b);
void badCharHeuristic( char *str, int size, int badchar[NO_OF_CHARS]);
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0;
int flag = 0;
int pkt_count = 0;
int pkt_dum = 0;

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"


#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

// for the 2 rings required for af_xdp
struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

// just stats to pring
struct stats_record {
	uint64_t timestamp;
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t tx_packets;
	uint64_t tx_bytes;
    // we can put bool type here if true, packet matched, if false, packet did not match
    int match[64];
};


struct xsk_socket_info {
	struct xsk_ring_cons rx; // rx ring
	struct xsk_ring_prod tx; // tx ring
	struct xsk_umem_info *umem; //allocated mem
	struct xsk_socket *xsk; // af_xdp socket

	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;

	uint32_t outstanding_tx;

	struct stats_record stats;
	struct stats_record prev_stats;
};

static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod *r)
{
	r->cached_cons = *r->consumer + r->size;
	return r->cached_cons - r->cached_prod;
}

static const char *__doc__ = "AF_XDP kernel bypass example\n";

static const struct option_wrapper long_options[] = {

	{{"help",	 no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",	 required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",	 no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",	 no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",	 no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"copy",        no_argument,		NULL, 'c' },
	 "Force copy mode"},

	{{"zero-copy",	 no_argument,		NULL, 'z' },
	 "Force zero-copy mode"},

	{{"queue",	 required_argument,	NULL, 'Q' },
	 "Configure interface receive queue for AF_XDP, default=0"},

	{{"poll-mode",	 no_argument,		NULL, 'p' },
	 "Use the poll() API waiting for packets to arrive"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"quiet",	 no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progsec",	 required_argument,	NULL,  2  },
	 "Load program in <section> of the ELF file", "<section>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

static bool global_exit;

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
	struct xsk_umem_info *umem;
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return NULL;

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, NULL);
	if (ret) {
		errno = -ret;
		return NULL;
	}

	umem->buffer = buffer;
	return umem;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
	uint64_t frame;
	if (xsk->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
	xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
	return frame;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
	assert(xsk->umem_frame_free < NUM_FRAMES);

	xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk)
{
	return xsk->umem_frame_free;
}

static struct xsk_socket_info *xsk_configure_socket(struct config *cfg,
						    struct xsk_umem_info *umem)
{
	struct xsk_socket_config xsk_cfg;
	struct xsk_socket_info *xsk_info;
	uint32_t idx;
	uint32_t prog_id = 0;
	int i;
	int ret;

	xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;

	xsk_info->umem = umem;
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.libbpf_flags = 0;
	xsk_cfg.xdp_flags = cfg->xdp_flags;
	xsk_cfg.bind_flags = cfg->xsk_bind_flags;
	ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
				 cfg->xsk_if_queue, umem->umem, &xsk_info->rx,
				 &xsk_info->tx, &xsk_cfg);

	if (ret)
		goto error_exit;

	ret = bpf_get_link_xdp_id(cfg->ifindex, &prog_id, cfg->xdp_flags);
	if (ret)
		goto error_exit;

	/* Initialize umem frame allocation */

	for (i = 0; i < NUM_FRAMES; i++)
		xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

	xsk_info->umem_frame_free = NUM_FRAMES;

	/* Stuff the receive path with buffers, we assume we have enough */
	ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
				     XSK_RING_PROD__DEFAULT_NUM_DESCS,
				     &idx);

	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
		goto error_exit;

	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++)
		*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
			xsk_alloc_umem_frame(xsk_info);

	xsk_ring_prod__submit(&xsk_info->umem->fq,
			      XSK_RING_PROD__DEFAULT_NUM_DESCS);

	return xsk_info;

error_exit:
	errno = -ret;
	return NULL;
}

static void complete_tx(struct xsk_socket_info *xsk)
{
	unsigned int completed;
	uint32_t idx_cq;

	if (!xsk->outstanding_tx)
		return;

	sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);


	// Collect/free completed TX buffers //
	completed = xsk_ring_cons__peek(&xsk->umem->cq,
					XSK_RING_CONS__DEFAULT_NUM_DESCS,
					&idx_cq);

	if (completed > 0) {
		for (int i = 0; i < completed; i++)
			xsk_free_umem_frame(xsk,
					    *xsk_ring_cons__comp_addr(&xsk->umem->cq,
								      idx_cq++));

		xsk_ring_cons__release(&xsk->umem->cq, completed);
		xsk->outstanding_tx -= completed < xsk->outstanding_tx ?
			completed : xsk->outstanding_tx;
	}
}

static inline __sum16 csum16_add(__sum16 csum, __be16 addend)
{
	uint16_t res = (uint16_t)csum;

	res += (__u16)addend;
	return (__sum16)(res + (res < (__u16)addend));
}

static inline __sum16 csum16_sub(__sum16 csum, __be16 addend)
{
	return csum16_add(csum, ~addend);
}

static inline void csum_replace2(__sum16 *sum, __be16 old, __be16 new)
{
	*sum = ~csum16_add(csum16_sub(~(*sum), old), new);
}

static bool process_packet(struct xsk_socket_info *xsk,
			   uint64_t addr, uint32_t len)
{
	uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr); // start of data
	unsigned int payload_size;
    unsigned char *payload;
    struct udphdr *udp;
    struct iphdr *ip;

	//struct ethhdr *eth = (struct ethhdr *) pkt;
	struct ethhdr *eth = pkt;
    ip = pkt + sizeof(*eth);
    udp = (void *)ip + sizeof(*ip);
	payload = (unsigned char *)udp + sizeof(*udp);
    payload_size = ntohs(udp->len) - sizeof(*udp);
	check_pattern(payload, payload_size);
	udp++;

	if (flag == 0)
        xsk->stats.match[pkt_dum] = 0; // pattern not found
    else
        xsk->stats.match[pkt_dum] = 1; // pattern found 
	
	pkt_dum++;
	return false;
}

/*static bool ProcessPacket(unsigned char* buffer, int size) {
    //Get the IP Header part of this packet
    struct iphdr *iph = (struct iphdr*)buffer;
    ++total;
    switch (iph->protocol) { //Check the Protocol and do accordingly...
        case 17: //UDP Protocol
            if(!process_udp_packet(buffer , size))
                return false; // pattern not found
            else
                return true; // pattern found   
 
        default: //Some Other Protocol like ARP etc.
            ++others;
            return false;
    }
}*/
 
 
/*static bool process_udp_packet(unsigned char *Buffer , int Size) {
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
 
    struct udphdr *udph = (struct udphdr *)(Buffer + iphdrlen);
 
    if(ntohs(udph->dest) != 5201)
        return false;
    else{
        check_pattern(Buffer + iphdrlen + sizeof(udph) , ( Size - sizeof udph - iph->ihl * 4));
        if (flag == 0)
            return false; // pattern not found
        else
            return true; // pattern found 
    }                     
}*/

void check_pattern(unsigned char *data, int Size) {
    char *pattern = NULL;
    FILE *fp;
    fp = fopen("pats.txt", "r");
    flag = 0;
    size_t len = 0;
    ssize_t read;

    while ((read = getline(&pattern, &len, fp)) != -1) {
    int m = strlen(pattern);
    int n = Size;

    int badchar[NO_OF_CHARS];

    /* Fill the bad character array by calling
        the preprocessing function badCharHeuristic()        
        for given pattern */
    badCharHeuristic(pattern, m, badchar);

    int s = 0;  // s is shift of the pattern with
                    
    // respect to text
    while(s <= (n - m))
    {
        int j = m-1;

        /* Keep reducing index j of pattern while
        characters of pattern and text are
        matching at this shift s */
        while(j >= 0 && pattern[j] == data[s+j])
            j--;

        /* If the pattern is present at current
        shift, then index j will become -1 after
        the above loop */
        if (j < 0)
        {
            //printf("\n pattern occurs at shift = %d", s);
            flag = 1;
            /* Shift the pattern so that the next
            character in text aligns with the last
            occurrence of it in pattern.
            The condition s+m < n is necessary for
            the case when pattern occurs at the end
            of text */
            s += (s+m < n)? m-badchar[data[s+m]] : 1;

        }                             
        else
            /* Shift the pattern so that the bad character
            in text aligns with the last occurrence of
            it in pattern. The max function is used to
            make sure that we get a positive shift.
            We may get a negative shift if the last
            occurrence  of bad character in pattern
            is on the right side of the current
            character. */
            s += max(1, j - badchar[data[s+j]]);
    }
}
}

// A utility function to get maximum of two integers
int max (int a, int b) { return (a > b)? a: b; }

// The preprocessing function for Boyer Moore's
// bad character heuristic
void badCharHeuristic( char *str, int size, int badchar[NO_OF_CHARS])
{
    int i;

    // Initialize all occurrences as -1
    for (i = 0; i < NO_OF_CHARS; i++)
        badchar[i] = -1;

    // Fill the actual value of last occurrence
    // of a character
    for (i = 0; i < size; i++)
        badchar[(int) str[i]] = i;
}                                    

static void handle_receive_packets(struct xsk_socket_info *xsk)
{
	unsigned int rcvd, stock_frames, i;
	uint32_t idx_rx = 0, idx_fq = 0;
	int ret;

	pkt_count = rcvd;
	pkt_dum = 0;

	rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
	if (!rcvd)
		return;

	/* Stuff the ring with as much frames as possible */
	stock_frames = xsk_prod_nb_free(&xsk->umem->fq,
					xsk_umem_free_frames(xsk));

	if (stock_frames > 0) {

		ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames,
					     &idx_fq);

		/* This should not happen, but just in case */
		while (ret != stock_frames)
			ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd,
						     &idx_fq);

		for (i = 0; i < stock_frames; i++)
			*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
				xsk_alloc_umem_frame(xsk);

		xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
	}

	/* Process received packets */
	for (i = 0; i < rcvd; i++) {
		uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

		if (!process_packet(xsk, addr, len))
			xsk_free_umem_frame(xsk, addr);

		xsk->stats.rx_bytes += len;
	}

	xsk_ring_cons__release(&xsk->rx, rcvd);
	xsk->stats.rx_packets += rcvd;

	/* Do we need to wake up the kernel for transmission */
	complete_tx(xsk);
  }

static void rx_and_process(struct config *cfg,
			   struct xsk_socket_info *xsk_socket)
{
	struct pollfd fds[2];
	int ret, nfds = 1;

	memset(fds, 0, sizeof(fds));
	fds[0].fd = xsk_socket__fd(xsk_socket->xsk);
	fds[0].events = POLLIN;

	while(!global_exit) {
		if (cfg->xsk_poll_mode) {
			ret = poll(fds, nfds, -1);
			if (ret <= 0 || ret > 1)
				continue;
		}
		handle_receive_packets(xsk_socket);
	}
}

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static uint64_t gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (uint64_t) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static double calc_period(struct stats_record *r, struct stats_record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

static void stats_print(struct stats_record *stats_rec,
			struct stats_record *stats_prev)
{
	uint64_t packets, bytes;
	double period;
	double pps; /* packets per sec */
	double bps; /* bits per sec */

	char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
		" %'11lld Kbytes (%'6.0f Mbits/s)"
		" period:%f\n";

	period = calc_period(stats_rec, stats_prev);
	if (period == 0)
		period = 1;

	packets = stats_rec->rx_packets - stats_prev->rx_packets;
	pps     = packets / period;

	bytes   = stats_rec->rx_bytes   - stats_prev->rx_bytes;
	bps     = (bytes * 8) / period / 1000000;

	printf(fmt, "AF_XDP RX:", stats_rec->rx_packets, pps,
	       stats_rec->rx_bytes / 1000 , bps,
	       period);

	packets = stats_rec->tx_packets - stats_prev->tx_packets;
	pps     = packets / period;

	bytes   = stats_rec->tx_bytes   - stats_prev->tx_bytes;
	bps     = (bytes * 8) / period / 1000000;

	printf(fmt, "       TX:", stats_rec->tx_packets, pps,
	       stats_rec->tx_bytes / 1000 , bps,
	       period);
	int i;
	for(i=0; i < pkt_count; i++){
    	if(stats_rec->match[i] == 0)
        	printf("No pattern found.");
    	else
        	printf("Pattern found.");
	}

	printf("\n");


}

static void *stats_poll(void *arg)
{
	unsigned int interval = 2;
	struct xsk_socket_info *xsk = arg;
	static struct stats_record previous_stats = { 0 };

	previous_stats.timestamp = gettime();

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	while (!global_exit) {
		sleep(interval);
		xsk->stats.timestamp = gettime();
		stats_print(&xsk->stats, &previous_stats);
		previous_stats = xsk->stats;
	}
	return NULL;
}

static void exit_application(int signal)
{
	signal = signal;
	global_exit = true;
}

int main(int argc, char **argv)
{
	int ret;
	int xsks_map_fd; // map file descriptor
	void *packet_buffer;
	uint64_t packet_buffer_size;
	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
	struct config cfg = {
		.ifindex   = -1,
		.do_unload = false,
		.filename = "",
		.progsec = "xdp_sock"
	};
	struct xsk_umem_info *umem;
	struct xsk_socket_info *xsk_socket;
	struct bpf_object *bpf_obj = NULL;
	pthread_t stats_poll_thread; // i dont think i need this

	/* Global shutdown handler */
	signal(SIGINT, exit_application);

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERROR: Required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	/* Unload XDP program if requested */
	if (cfg.do_unload)
		return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

	/* Load custom program if configured */
    // loads xdp object in specified dev 
	if (cfg.filename[0] != 0) {
		struct bpf_map *map;

		bpf_obj = load_bpf_and_xdp_attach(&cfg);
		if (!bpf_obj) {
			/* Error handling done in load_bpf_and_xdp_attach() */
			exit(EXIT_FAILURE);
		}

		/* We also need to load the xsks_map */
		map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
		xsks_map_fd = bpf_map__fd(map);
		if (xsks_map_fd < 0) {
			fprintf(stderr, "ERROR: no xsks map found: %s\n",
				strerror(xsks_map_fd));
			exit(EXIT_FAILURE);
		}
	}

	/* Allow unlimited locking of memory, so all memory needed for packet
	 * buffers can be locked.
	 */
	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Allocate memory for NUM_FRAMES of the default XDP frame size */
	packet_buffer_size = NUM_FRAMES * FRAME_SIZE; // 4096 * xdp default frame size
	if (posix_memalign(&packet_buffer,
			   getpagesize(), /* PAGE_SIZE aligned */
			   packet_buffer_size)) {
		fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Initialize shared packet_buffer for umem usage */
	umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
	if (umem == NULL) {
		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Open and configure the AF_XDP (xsk) socket */
	xsk_socket = xsk_configure_socket(&cfg, umem);
	if (xsk_socket == NULL) {
		fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Start thread to do statistics display */
    // can be created to a thread that prints out if pattern is matched
    // not needed 
	if (verbose) {
		ret = pthread_create(&stats_poll_thread, NULL, stats_poll,
				     xsk_socket);
		if (ret) {
			fprintf(stderr, "ERROR: Failed creating statistics thread "
				"\"%s\"\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	/* Receive and count packets than drop them */
    // where to put udp processing
	rx_and_process(&cfg, xsk_socket);

	/* Cleanup */
	xsk_socket__delete(xsk_socket->xsk);
	xsk_umem__delete(umem->umem);
	xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

	return EXIT_OK;
}