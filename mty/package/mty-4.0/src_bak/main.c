/* horst - Highly Optimized Radio Scanning Tool
 *
 * Copyright (C) 2005-2014 Bruno Randolf (br1@einfach.org)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <sys/time.h>
#include <errno.h>
#include <err.h>
#include <sys/socket.h>

#include "main.h"
#include "util.h"
#include "capture.h"
#include "protocol_parser.h"
#include "network.h"
#include "display.h"
#include "wlan_util.h"
#include "ieee80211_util.h"
#include "control.h"
#include "channel.h"
#include "node.h"
#include "essid.h"


struct list_head nodes;
struct essid_meta_info essids;
struct history hist;
struct statistics stats;
struct channel_info spectrum[MAX_CHANNELS];

struct config conf = {
	.node_timeout		= NODE_TIMEOUT,
	.channel_time		= CHANNEL_TIME,
	.ifname			= INTERFACE_NAME,
	.display_interval	= DISPLAY_UPDATE_INTERVAL,
	.recv_buffer_size	= RECV_BUFFER_SIZE,
	.port			= DEFAULT_PORT,
	.control_pipe		= DEFAULT_CONTROL_PIPE,
	.filter_pkt		= PKT_TYPE_ALL,
	.filter_mode		= WLAN_MODE_ALL,
	.printlog		= 0,
};

struct timeval the_time;

int mon; /* monitoring socket */

// dump file
static FILE* DF = NULL;
// bedo buffer(debug) file
static FILE* BF = NULL;
// virtual account(SNS+IM)
static FILE* VF = NULL;

/* receive packet buffer
 *
 * due to the way we receive packets the network (TCP connection) we have to
 * expect the reception of partial packet as well as the reception of several
 * packets at one. thus we implement a buffered receive where partially received
 * data stays in the buffer.
 *
 * we need two buffers: one for packet capture or receiving from the server and
 * another one for data the clients sends to the server.
 *
 * not sure if this is also an issue with local packet capture, but it is not
 * implemented there.
 *
 * size: max 80211 frame (2312) + space for prism2 header (144)
 * or radiotap header (usually only 26) + some extra */
static unsigned char buffer[2312 + 200];
static size_t buflen;

/* for packets from client to server */
static unsigned char cli_buffer[500];
static size_t cli_buflen;

/* for select */
static fd_set read_fds;
static fd_set write_fds;
static fd_set excpt_fds;
static struct timeval tv;

/* bedo log level define */
static bedo_log_level gBedo_log_level = BEDO_LOG_INFO;

static bool virtual_acc_record(const char *type, const char *account, const char *mac);

#define qq_flag_len		4
static bool valid_qq(const unsigned char* qqbuf, int nums, unsigned char* qq);
static unsigned char* mem_find(const unsigned char *buffer, int buflen, const unsigned char *findmem, int findlen);
static bool qq_filter(const unsigned char *buffer, int buflen, struct packet_info* p, const char* wlan_src, const char* wlan_dst);
static bool taobao_filter(const unsigned char *buffer, int buflen, struct packet_info* p, const char* wlan_src, const char* wlan_dst);
static bool weixin_filter(const unsigned char *buffer, int buflen, struct packet_info* p, const char* wlan_src, const char* wlan_dst);

// search around AP 
static bool searchAP(struct around_ap_info **ppapinfo);
static int best_chan_from_APInfo(struct around_ap_info *apinfo);
static void freeAPs(struct around_ap_info *apinfo);

bool 
searchAP(struct around_ap_info **ppapinfo)
{
	int sysret;
	char buf[256], *pbuf;
	struct around_ap_info *apinfo = NULL, *tmpap = NULL;
	
	*ppapinfo = NULL;

	sysret = system("iw dev wlan0 scan > /tmp/APS");
	if (sysret == -1)
		return false;
	
	FILE *fp = fopen("/tmp/APS", "r");
	if (fp == NULL) {
		printlog("searchAP failed\n");
		return false;
	}	

	while(fgets(buf, sizeof(buf), fp)) {
		pbuf = buf;
		if (NULL != strstr(buf, "(on wlan0)")) {
			if (apinfo != NULL) {
				tmpap = apinfo;
				printlog("ap ssid=%s, signal=%d, channel=%d, encrypt=%s", apinfo->essid, 
					 apinfo->signal, apinfo->channel, apinfo->encrypt?"true":"false");
			}
			apinfo = malloc(sizeof(struct around_ap_info));
			apinfo->next = NULL;
			if (tmpap)
				tmpap->next = apinfo;
			if (*ppapinfo == NULL)
				*ppapinfo = apinfo; 
		}
		if (NULL != strstr(buf, "signal:")) {
			strsep(&pbuf, ":");
			apinfo->signal = atoi(pbuf);
		}
		if (NULL != strstr(buf, "SSID:")) {
			strsep(&pbuf, ":");
			pbuf = trim(pbuf);
			strcpy(apinfo->essid, pbuf);		
		}
		if (NULL != strstr(buf, "primary channel:")) {
			strsep(&pbuf, ":");
			apinfo->channel = atoi(pbuf);
		}
		if (NULL != strstr(buf, "RSN:") || NULL != strstr(buf, "WPA:")) {
			apinfo->encrypt = true;
		}
	}
	if (apinfo) 
		printlog("ap ssid=%s, signal=%d, channel=%d, encrypt=%s", apinfo->essid, 
			 apinfo->signal, apinfo->channel, apinfo->encrypt?"true":"false");

	fclose(fp);
	
	return true;
}

/*
  The best channel is the channel of AP which is not be encrypted and it's signal is strongest
*/
static int 
best_chan_from_APInfo(struct around_ap_info *apinfo)
{
	struct around_ap_info *ap, *bestap = NULL;
	
	if (apinfo == NULL)
		return -1;	

	bestap = apinfo;
	ap = apinfo->next;
	while(ap) {
		if (ap->encrypt == bestap->encrypt) {
			if (bestap->signal < ap->signal)
				bestap = ap;
		}
		else {
			if (false == ap->encrypt)
				bestap = ap;
		}
		ap = ap->next;
	}
	printlog("best matched AP:%s", bestap->essid);
	return bestap->channel;
}

static int
chan_from_assignssid(struct around_ap_info *apinfo, char *assignssid)
{
	struct around_ap_info *ap, *bestap = NULL;

	if (apinfo == NULL || assignssid == NULL)
		return -1;

	ap = apinfo;
	while(ap) {
		if (0 == strcmp(ap->essid, assignssid)) {
			if (bestap == NULL) 
				bestap = ap;
			else {
				if (bestap->signal < ap->signal)
					bestap = ap;
			} 	
		}
		ap = ap->next;
	}	
	if (bestap) {
		printlog("assigned ssid:%s, channel:%d", assignssid, bestap->channel);
		return bestap->channel;
	}
	return -1;
}


static void 
freeAPs(struct around_ap_info *apinfo)
{
	if (apinfo == NULL)
		return;

	struct around_ap_info *next, *cur;
	cur = apinfo;
	while((next = cur->next) != NULL) {
		free(cur);
		cur = next;
	}
	free(cur);
}


static unsigned char* 
mem_find(const unsigned char *buffer, int buflen, const unsigned char *findmem, int findlen)
{
	int i, j;
	unsigned char ch;
	bool match = false;

	if (buffer == NULL || buflen == 0)
		return NULL;

	for (i=0; i<buflen; i++) {
		if (buflen < (i+findlen))
			break;
		for (j=0; j<findlen; j++) {
			ch = *(buffer+i+j);
			if (ch != *(findmem+j))
				break;
		}
		if (j == findlen) {
			match = true;
			break;
		}
	}
	
	if (false == match)
		return NULL;

	return (buffer + i);
}

static bool 
valid_qq(const unsigned char* qqbuf, int nums, unsigned char* qq)
{
	// 4bytes ahead QQ is  length of QQ+04, qq length will be in [5, 18), so the length will be [0x9, 0x12) 
	static const unsigned char qqflag[3] = {0x00, 0x00, 0x00};
	int i, len=qq_flag_len-1, qqlen;
	unsigned char ch;
	bool ret = false;

	if (qqbuf == NULL || qq == NULL || nums < 5 || nums >= 18 )
		return ret;

	for (i=0; i<len; i++) {
		ch = qqflag[i];
		if (*(qqbuf+i) != ch) 
			break;
		if (i == len - 1)
			ret = true;
	}
	if (false == ret)
		return ret;

	ch = *(qqbuf+len);
	qqlen = ch - qq_flag_len;
	if (qqlen > nums || qqlen < 5 || qqlen > 14 || '0' == *(qqbuf+qq_flag_len))
		return false;
	
	for (i=0; i<qqlen; i++) {
		*(qq+i) = *(qqbuf+qq_flag_len+i);
	}
	*(qq+i) = 0x00;

	return ret;
}

static bool 
qq_filter(const unsigned char *buffer, int buflen, struct packet_info* p, const char* wlan_src, const char* wlan_dst)
{
	int i, j, nums;
	unsigned char qq[20];

	if (buffer == NULL || buflen <= 0)
		return false;

	for (i=0, nums=0; i<buflen; i++) {
		unsigned char ch;
		ch = *(buffer+i);
		if (ch>='0' && ch<='9' && ((i-nums)>qq_flag_len))
			nums++;
		else {
			if (nums >= 5 && nums < 20) {
				memset(qq, 0, 20);
				for (j=nums; j>0; j--) {
					qq[nums-j] = *(buffer+i-j);
				}
				//bedo_log(BEDO_LOG_INFO, "before valid, QQ=%s", qq);

				memset(qq, 0, 20);
				if (valid_qq(buffer+i-nums-qq_flag_len, nums, qq)) {
					char *bindmac = wlan_src;
					if (p->wlan_mode == WLAN_MODE_AP)
						bindmac = wlan_dst;
					printlog("QQ=%s, MAC=%s", qq, bindmac);
					bedo_log(BEDO_LOG_INFO,"QQ=%s, MAC=%s", qq, bindmac);
					virtual_acc_record("QQ", qq, bindmac);
				}
			}
			nums=0;
		}
	}	
	
	return true;
}

static bool 
taobao_filter(const unsigned char *buffer, int buflen, struct packet_info* p, const char* wlan_src, const char* wlan_dst)
{
	static const char *domain = "taobao.com", *host = "Host:";
	static const char *taobao_flags[] = {"_w_tb_nick=", "_nk_=", "lgc=", "tracknick="};
	static const char *taobao_endch = ";";
	static const unsigned char sep[] = {0x0d, 0x0a};
	int i, len, remain;
	unsigned char *pt, *pt1, *pt2;
	char account[128];

	if (buffer == NULL || buflen == 0)
		return false;

	remain = buflen;
	pt = mem_find(buffer, buflen, host, strlen(host));
	if (pt == NULL) {
		return false;
	}
	//printlog("Host find");
	pt = pt + strlen(host);
	remain = buflen - (pt - buffer);
	pt1 = mem_find(pt, remain, sep, 2);
	if (pt1 == NULL)
		return false;
	//printlog("0d0a find");

	len = pt1 - pt + 2;
	pt1 = mem_find(pt, len, domain, strlen(domain));
	if (pt1 == NULL)				// is not taobao domain
		return false;
	pt = pt + len;
	remain = remain - len;
	//printlog("domain find, domain=%s", pt1);
	bedo_log(BEDO_LOG_INFO,"domain find, domain=%s", pt1);

	memset(account, 0, 128);
	for (i=0; i<sizeof(taobao_flags)/sizeof(char*); i++) {
		const char *flag = taobao_flags[i];
		pt1 = mem_find(pt, remain, flag, strlen(flag));
		if (pt1 == NULL)
			continue;
		pt1 = pt1 + strlen(flag);
		pt2 = mem_find(pt1, buflen-(pt1-buffer), taobao_endch, 1); 
		if (pt2 == NULL || (pt2-pt1)>=128)
			continue;
		memset(account, 0, 128);
		memcpy(account, pt1, pt2-pt1);
		char *bindmac = wlan_src;
		if (p->wlan_mode == WLAN_MODE_AP)
			bindmac = wlan_dst;
		bedo_log(BEDO_LOG_INFO, "taobao=%s, MAC=%s", account, bindmac);
		printlog("taobao=%s, MAC=%s", account, bindmac);
		virtual_acc_record("TAOBAO", account, bindmac);
		break;
	}

	if (strlen(account) == 0)
		return false;

	return true;
}

static bool 
weixin_filter(const unsigned char *buffer, int buflen, struct packet_info* p, const char* wlan_src, const char* wlan_dst)
{

	return true;
}


static bool virtual_acc_record(const char *type, const char *account, const char *mac)
{
	if (VF == NULL)
		return false;

	if (type == NULL || account == NULL || mac == NULL)
		return false;

	struct timeval tv;
	char buf[200];
	
	memset(buf, 0, 200);
	gettimeofday(&tv, NULL);
	sprintf(buf, "%d, %s, %s, %s", tv.tv_sec, type, mac, account);		
	fprintf(VF, buf);
	fprintf(VF, "\n");
	fflush(VF);

	return true;
}

void __attribute__ ((format (printf, 1, 2)))
printlog(const char *fmt, ...)
{
	if (conf.printlog != 1)
		return;

	char buf[128];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(&buf[1], 127, fmt, ap);
	va_end(ap);

	if (conf.quiet || DO_DEBUG || !conf.display_initialized)
		printf("%s\n", &buf[1]);
	else {
		/* fix up string for display log */
		buf[0] = '\n';
		display_log(buf);
	}
}


static void
update_history(struct packet_info* p)
{
	if (p->phy_signal == 0)
		return;

	hist.signal[hist.index] = p->phy_signal;
	hist.noise[hist.index] = p->phy_noise;
	hist.rate[hist.index] = p->phy_rate;
	hist.type[hist.index] = (p->phy_flags & PHY_FLAG_BADFCS) ? 1 : p->wlan_type;
	hist.retry[hist.index] = p->wlan_retry;

	hist.index++;
	if (hist.index == MAX_HISTORY)
		hist.index = 0;
}


static void
update_statistics(struct packet_info* p)
{
	int type = (p->phy_flags & PHY_FLAG_BADFCS) ? 1 : p->wlan_type;

	if (p->phy_rate_idx == 0)
		return;

	stats.packets++;
	stats.bytes += p->wlan_len;
	if (p->wlan_retry)
		stats.retries++;

	if (p->phy_rate_idx > 0 && p->phy_rate_idx < MAX_RATES) {
		stats.duration += p->pkt_duration;
		stats.packets_per_rate[p->phy_rate_idx]++;
		stats.bytes_per_rate[p->phy_rate_idx] += p->wlan_len;
		stats.duration_per_rate[p->phy_rate_idx] += p->pkt_duration;
	}

	if (type >= 0 && type < MAX_FSTYPE) {
		stats.packets_per_type[type]++;
		stats.bytes_per_type[type] += p->wlan_len;
		if (p->phy_rate_idx > 0 && p->phy_rate_idx < MAX_RATES)
			stats.duration_per_type[type] += p->pkt_duration;
	}
}


static void
update_spectrum(struct packet_info* p, struct node_info* n)
{
	struct channel_info* chan;
	struct chan_node* cn;

	if (p->pkt_chan_idx < 0)
		return; /* chan not found */

	chan = &spectrum[p->pkt_chan_idx];
	chan->signal = p->phy_signal;
	chan->noise = p->phy_noise;
	chan->packets++;
	chan->bytes += p->wlan_len;
	chan->durations += p->pkt_duration;
	ewma_add(&chan->signal_avg, -chan->signal);

	if (!n) {
		DEBUG("spec no node\n");
		return;
	}

	/* add node to channel if not already there */
	list_for_each(&chan->nodes, cn, chan_list) {
		if (cn->node == n) {
			DEBUG("SPEC node found %p\n", cn->node);
			break;
		}
	}
	if (cn->node != n) {
		DEBUG("SPEC node adding %p\n", n);
		cn = malloc(sizeof(struct chan_node));
		cn->node = n;
		cn->chan = chan;
		ewma_init(&cn->sig_avg, 1024, 8);
		list_add_tail(&chan->nodes, &cn->chan_list);
		list_add_tail(&n->on_channels, &cn->node_list);
		chan->num_nodes++;
		n->num_on_channels++;
	}
	/* keep signal of this node as seen on this channel */
	cn->sig = p->phy_signal;
	ewma_add(&cn->sig_avg, -cn->sig);
	cn->packets++;
}


void
update_spectrum_durations(void)
{
	/* also if channel was not changed, keep stats only for every channel_time.
	 * display code uses durations_last to get a more stable view */
	if (conf.channel_idx >= 0) {
		spectrum[conf.channel_idx].durations_last =
				spectrum[conf.channel_idx].durations;
		spectrum[conf.channel_idx].durations = 0;
		ewma_add(&spectrum[conf.channel_idx].durations_avg,
			 spectrum[conf.channel_idx].durations_last);
	}
}


static void 
write_to_file(struct packet_info* p)
{
	fprintf(DF, "%d, ", the_time.tv_sec);
	fprintf(DF, "%s, %s, ",
		get_packet_type_name(p->wlan_type), ether_sprintf(p->wlan_src));
	fprintf(DF, "%s, ", ether_sprintf(p->wlan_dst));
	fprintf(DF, "%s, %d", p->wlan_essid,  p->phy_signal);
	
	fprintf(DF, ", mode=%d, channel=%d, wep=%d, wpa=%d, rsn=%d",
		p->wlan_mode, p->wlan_channel,
		p->wlan_wep, p->wlan_wpa, p->wlan_rsn);
	
	//fprintf(DF, "%s, ", ether_sprintf(p->wlan_bssid));
	//fprintf(DF, "%x, %d, %d, %d, %d, %d, %d, ",
	//	p->pkt_types, p->phy_signal, p->phy_noise, p->phy_snr,
	//	p->wlan_len, p->phy_rate, p->phy_freq);
	//fprintf(DF, "%016llx, ", (unsigned long long)p->wlan_tsf);
	//fprintf(DF, "%s, %d, %d, %d, %d, %d, ",
	//	p->wlan_essid, p->wlan_mode, p->wlan_channel,
	//	p->wlan_wep, p->wlan_wpa, p->wlan_rsn);
	//fprintf(DF, "%s, ", ip_sprintf(p->ip_src));
	//fprintf(DF, "%s, ", ip_sprintf(p->ip_dst));
	//fprintf(DF, "%d, %d\n", p->olsr_type, p->olsr_neigh);
	fprintf(DF, "\n");
	fflush(DF);
}


/* return 1 if packet is filtered */
static int
filter_packet(struct packet_info* p)
{
	int i;

	if (conf.filter_off)
		return 0;

	if (conf.filter_pkt != PKT_TYPE_ALL && (p->pkt_types & ~conf.filter_pkt)) {
		stats.filtered_packets++;
		return 1;
	}

	/* cannot trust anything if FCS is bad */
	if (p->phy_flags & PHY_FLAG_BADFCS)
		return 0;

	if (conf.filter_mode != WLAN_MODE_ALL && ((p->wlan_mode & ~conf.filter_mode) || p->wlan_mode == 0)) {
		/* this also filters out packets where we cannot associate a mode (ACK, RTS/CTS) */
		stats.filtered_packets++;
		return 1;
	}

	if (MAC_NOT_EMPTY(conf.filterbssid) &&
	    memcmp(p->wlan_bssid, conf.filterbssid, MAC_LEN) != 0) {
		stats.filtered_packets++;
		return 1;
	}

	if (conf.do_macfilter) {
		for (i = 0; i < MAX_FILTERMAC; i++) {
			if (MAC_NOT_EMPTY(p->wlan_src) &&
			    conf.filtermac_enabled[i] &&
			    memcmp(p->wlan_src, conf.filtermac[i], MAC_LEN) == 0) {
				return 0;
			}
		}
		stats.filtered_packets++;
		return 1;
	}
	return 0;
}

void
handle_buffer(char *p, int len, int lnlen, bool addbin)
{
	if (BF == NULL)
		return;

	int i, j;
	time_t timer;
	struct tm *t_tm;
	char cur_t[128];

	timer = time(NULL);
	t_tm = localtime(&timer);
	memset(cur_t, 0, 128);
	sprintf(cur_t, "%4d-%02d-%02d %02d:%02d:%02d", t_tm->tm_year+1900, t_tm->tm_mon+1, t_tm->tm_mday, t_tm->tm_hour, t_tm->tm_min, t_tm->tm_sec);
	fprintf(BF, "---%s---", cur_t);

	for (i = 0; i < len; i++) {
		//if ((i % 2) == 0) {
		//        fprintf(BF, " ");
		//}
		if ((i % lnlen) == 0 || (i == len-1)) {
			if (addbin && i > 0) {
				char buf[lnlen];
				fprintf(BF, "    ");
				for (j=0; j<lnlen; j++) {
					char ch = *(p+i-lnlen+j);
					if (ch == 0x0d || ch == 0x0a)
						ch = 0x2e;
					buf[j] = ch;
				}
				fwrite(buf, lnlen, 1, BF);
			}
			fprintf(BF, "\n");
		}
		fprintf(BF ,"%02x", *((unsigned char*)(p+i)));
	}
	fprintf(BF, "\n");
}

void __attribute__ ((format (printf, 2, 3)))
bedo_log(bedo_log_level level, const char *fmt, ...)
{
#if BEDO_DEBUG	
	int i, j;
	time_t timer;
	struct tm *t_tm;
	char cur_t[128];
	va_list ap;

	if (BF == NULL)
		return;
	
	if (gBedo_log_level > level)
		return;     // do nothing 
	va_start(ap, fmt);
		
	timer = time(NULL);
	t_tm = localtime(&timer);
	memset(cur_t, 0, 128);
	sprintf(cur_t, "%4d-%02d-%02d %02d:%02d:%02d", t_tm->tm_year+1900, t_tm->tm_mon+1, t_tm->tm_mday, t_tm->tm_hour, t_tm->tm_min, t_tm->tm_sec);
	fprintf(BF, "---%s---\n", cur_t);

	vfprintf(BF, fmt, ap);
	fprintf(BF, "\n");
	va_end(ap);
#endif
}


void
handle_packet(struct packet_info* p)
{
	struct node_info* n = NULL;
	int i = -1;

	/* filter on server side only */
	if (!conf.serveraddr && filter_packet(p)) {
		if (!conf.quiet && !conf.paused && !DO_DEBUG)
			update_display_clock();
		return;
	}

	if (cli_fd != -1)
		net_send_packet(p);

	if (conf.dumpfile != NULL && !conf.paused && DF != NULL)
		write_to_file(p);

	if (conf.paused)
		return;

	DEBUG("handle %s\n", get_packet_type_name(p->wlan_type));

	/* get channel index for packet */
	if (p->phy_freq) {
		i = channel_find_index_from_freq(p->phy_freq);
	}
	/* not found from pkt, best guess from config but it might be
	 * unknown (-1) too */
	if (i < 0)
		p->pkt_chan_idx = conf.channel_idx;
	else
		p->pkt_chan_idx = i;
	/* wlan_channel is only known for beacons and probe response,
	 * otherwise we set it from the physical channel */
	if (p->wlan_channel == 0 && p->pkt_chan_idx >= 0)
		p->wlan_channel = channel_get_chan_from_idx(p->pkt_chan_idx);

	/* detect if noise reading is present or not */
	if (!conf.have_noise && p->phy_noise)
		conf.have_noise = 1;

	/* if current channel is unknown (this is a mac80211 bug), guess it from
	 * the packet */
	if (conf.channel_idx < 0 && p->pkt_chan_idx >= 0)
		conf.channel_idx = p->pkt_chan_idx;

	if (!(p->phy_flags & PHY_FLAG_BADFCS)) {
		/* we can't trust any fields except phy_* of packets with bad FCS,
		 * so we can't do all this here */
		n = node_update(p);

		if (n)
			p->wlan_retries = n->wlan_retries_last;

		p->pkt_duration = ieee80211_frame_duration(
				p->phy_flags & PHY_FLAG_MODE_MASK,
				p->wlan_len, p->phy_rate,
				p->phy_flags & PHY_FLAG_SHORTPRE,
				0 /*shortslot*/, p->wlan_type,
				p->wlan_qos_class,
				p->wlan_retries);
	}

	update_history(p);
	update_statistics(p);
	update_spectrum(p, n);
	update_essids(p, n);

#if !DO_DEBUG
	if (!conf.quiet)
		update_display(p);
#endif
}


static void
local_receive_packet(int fd, unsigned char* buffer, size_t bufsize)
{
	int len;
	struct packet_info p;
	const unsigned char kMyMac[] = {0x28, 0xe0, 0x2c, 0xc7, 0x18, 0xa0};
	unsigned char wlan_src[18], wlan_dst[18];

	len = recv_packet(fd, buffer, bufsize);

#if DO_DEBUG
	dump_packet(buffer, len);
#endif
	memset(&p, 0, sizeof(p));

	if (!parse_packet(buffer, len, &p)) {
		DEBUG("parsing failed\n");
		return;
	}

	handle_packet(&p);

	memset(wlan_src, 0, 18);
	memset(wlan_dst, 0, 18);
	memcpy(wlan_src, ether_sprintf(p.wlan_src), 17);
	memcpy(wlan_dst, ether_sprintf(p.wlan_dst), 17);
	/*
	bedo_log(BEDO_LOG_INFO, "wlan_src:%s, wlan_dst:%s, mymac=%s", wlan_src, 
		p.wlan_dst, ether_sprintf(kMyMac));
	if ((memcmp(p.wlan_src, kMyMac, 6)==0) || (memcmp(p.wlan_dst, kMyMac, 6) == 0)) {	
		bedo_log(BEDO_LOG_INFO, "same wlan_src:%s, wlan_dst:%s", wlan_src, wlan_dst);
	}
	*/
	if (((p.pkt_types&PKT_TYPE_DATA) == PKT_TYPE_DATA) 
		&& (((p.pkt_types&PKT_TYPE_TCP) == PKT_TYPE_TCP)||((p.pkt_types&PKT_TYPE_UDP)== PKT_TYPE_UDP))
		/*&& ((memcmp(p.wlan_src, kMyMac, 6)==0) || (memcmp(p.wlan_dst, kMyMac, 6) == 0))*/
		&& (p.wlan_mode == WLAN_MODE_STA)) {
		handle_buffer(buffer, len, 32, true);

		bedo_log(BEDO_LOG_INFO, "pkt_types=%08x, pkt_types&PKT_TYPE_TCP=%08x, wlan_src:%s, wlan_dst:%s",
			  p.pkt_types, p.pkt_types&PKT_TYPE_TCP, wlan_src, wlan_dst);
		qq_filter(buffer, len, &p, wlan_src, wlan_dst);
		taobao_filter(buffer, len, &p, wlan_src, wlan_dst);
		weixin_filter(buffer, len, &p, wlan_src, wlan_dst);
	}
}


static void
receive_any(void)
{
	int ret, mfd;

	FD_ZERO(&read_fds);
	FD_ZERO(&write_fds);
	FD_ZERO(&excpt_fds);
	if (!conf.quiet && !DO_DEBUG)
		FD_SET(0, &read_fds);
	FD_SET(mon, &read_fds);
	if (srv_fd != -1)
		FD_SET(srv_fd, &read_fds);
	if (cli_fd != -1)
		FD_SET(cli_fd, &read_fds);
	if (ctlpipe != -1)
		FD_SET(ctlpipe, &read_fds);

	tv.tv_sec = 0;
	tv.tv_usec = min(conf.channel_time, 1000000);
	mfd = max(mon, srv_fd);
	mfd = max(mfd, ctlpipe);
	mfd = max(mfd, cli_fd) + 1;

	ret = select(mfd, &read_fds, &write_fds, &excpt_fds, &tv);
	if (ret == -1 && errno == EINTR) /* interrupted */
		return;
	if (ret == 0) { /* timeout */
		if (!conf.quiet && !DO_DEBUG)
			update_display_clock();
		return;
	}
	else if (ret < 0) /* error */
		err(1, "select()");

	/* stdin */
	if (FD_ISSET(0, &read_fds) && !conf.quiet && !DO_DEBUG)
		handle_user_input();

	/* local packet or client */
	if (FD_ISSET(mon, &read_fds)) {
		if (conf.serveraddr)
			net_receive(mon, buffer, &buflen, sizeof(buffer));
		else
			local_receive_packet(mon, buffer, sizeof(buffer));
	}

	/* server */
	if (srv_fd > -1 && FD_ISSET(srv_fd, &read_fds))
		net_handle_server_conn();

	/* from client to server */
	if (cli_fd > -1 && FD_ISSET(cli_fd, &read_fds))
		net_receive(cli_fd, cli_buffer, &cli_buflen, sizeof(cli_buffer));

	/* named pipe */
	if (ctlpipe > -1 && FD_ISSET(ctlpipe, &read_fds))
		control_receive_command();
}


void
free_lists(void)
{
	int i;
	struct essid_info *e, *f;
	struct node_info *ni, *mi;
	struct chan_node *cn, *cn2;

	/* free node list */
	list_for_each_safe(&nodes, ni, mi, list) {
		DEBUG("free node %s\n", ether_sprintf(ni->last_pkt.wlan_src));
		list_del(&ni->list);
		free(ni);
	}

	/* free essids */
	list_for_each_safe(&essids.list, e, f, list) {
		DEBUG("free essid '%s'\n", e->essid);
		list_del(&e->list);
		free(e);
	}

	/* free channel nodes */
	for (i = 0; i < conf.num_channels; i++) {
		list_for_each_safe(&spectrum[i].nodes, cn, cn2, chan_list) {
			DEBUG("free chan_node %p\n", cn);
			list_del(&cn->chan_list);
			cn->chan->num_nodes--;
			free(cn);
		}
	}
}


static void
finish_all(void)
{
	free_lists();

	if (!conf.serveraddr)
		close_packet_socket(mon, conf.ifname);

	if (DF != NULL) {
		fclose(DF);
		DF = NULL;
	}

	if (BF != NULL) {
		fclose(BF);
		BF = NULL;
	}
	
	if (VF != NULL) {
		fclose(VF);
		VF = NULL;
	}

	if (conf.allow_control)
		control_finish();

#if !DO_DEBUG
	net_finish();

	if (!conf.quiet)
		finish_display();
#endif
}


static void
exit_handler(void)
{
	finish_all();
}


static void
sigint_handler(__attribute__((unused)) int sig)
{
	exit(0);
}


static void
sigpipe_handler(__attribute__((unused)) int sig)
{
	/* ignore signal here - we will handle it after write failed */
}


static void
get_options(int argc, char** argv)
{
	int c;
	static int n;

	while((c = getopt(argc, argv, "hqsCPi:t:c:p:e:f:d:o:b:X::x:m:u:U:a:l:v:A:")) > 0) {
		switch (c) {
		case 'p':
			conf.port = optarg;
			break;
		case 'P':
			conf.printlog = 1;
			break;
		case 'q':
			conf.quiet = 1;
			break;
		case 'i':
			conf.ifname = optarg;
			break;
		case 'o':
			conf.dumpfile = optarg;
			break;
		case 't':
			conf.node_timeout = atoi(optarg);
			break;
		case 'b':
			conf.recv_buffer_size = atoi(optarg);
			break;
		case 'l':
			conf.bedologfile = optarg;
			break;
		case 'v':
			conf.viraccfile = optarg;
			break;
		case 's':
			conf.do_change_channel = 1;
			break;
		case 'd':
			conf.display_interval = atoi(optarg) * 1000;
			break;
		case 'e':
			if (n >= MAX_FILTERMAC)
				break;
			conf.do_macfilter = 1;
			convert_string_to_mac(optarg, conf.filtermac[n]);
			conf.filtermac_enabled[n] = 1;
			n++;
			break;
		case 'c':
			conf.serveraddr = optarg;
			break;
		case 'C':
			conf.allow_client = 1;
			break;
		case 'X':
			if (optarg != NULL)
				conf.control_pipe = optarg;
			conf.allow_control = 1;
			break;
		case 'x':
			control_send_command(optarg);
			exit(0);
		case 'A':
			if (optarg != NULL) {
				char *psid = NULL;
				if (0 == strcmp(optarg, "strong"))
					/* match strongest free wifi */
					conf.automatchchannel = 1; 
				else if (NULL != (psid = strstr(optarg, "ssid_"))) {
					/* match assigned ssid */ 
					conf.automatchchannel = 2;
					strcpy(conf.assign_ssid, optarg+strlen("ssid_"));  
					printlog("conf.assign_ssid=%s", conf.assign_ssid);
				}
			}
			if (conf.automatchchannel > 0) {
				conf.control_pipe = "/tmp/horst_channel";
				conf.allow_control = 1;
			}
			break;
		case 'm':
			if (conf.filter_mode == WLAN_MODE_ALL)
				conf.filter_mode = 0;
			if (strcmp(optarg, "AP") == 0)
				conf.filter_mode |= WLAN_MODE_AP;
			else if (strcmp(optarg, "STA") == 0)
				conf.filter_mode |= WLAN_MODE_STA;
			else if (strcmp(optarg, "ADH") == 0 || strcmp(optarg, "IBSS") == 0)
				conf.filter_mode |= WLAN_MODE_IBSS;
			else if (strcmp(optarg, "PRB") == 0)
				conf.filter_mode |= WLAN_MODE_PROBE;
			else if (strcmp(optarg, "WDS") == 0)
				conf.filter_mode |= WLAN_MODE_4ADDR;
			else if (strcmp(optarg, "UNKNOWN") == 0)
				conf.filter_mode |= WLAN_MODE_UNKNOWN;
			break;
		case 'f':
			if (conf.filter_pkt == PKT_TYPE_ALL)
				conf.filter_pkt = 0;
			if (strcmp(optarg, "CTRL") == 0 || strcmp(optarg, "CONTROL") == 0)
				conf.filter_pkt |= PKT_TYPE_CTRL | PKT_TYPE_ALL_CTRL;
			else if (strcmp(optarg, "MGMT") == 0 || strcmp(optarg, "MANAGEMENT") == 0)
				conf.filter_pkt |= PKT_TYPE_MGMT | PKT_TYPE_ALL_MGMT;
			else if (strcmp(optarg, "DATA") == 0)
				conf.filter_pkt |= PKT_TYPE_DATA | PKT_TYPE_ALL_DATA;
			else if (strcmp(optarg, "BADFCS") == 0)
				conf.filter_pkt |= PKT_TYPE_BADFCS;
			else if (strcmp(optarg, "BEACON") == 0)
				conf.filter_pkt |= PKT_TYPE_BEACON;
			else if (strcmp(optarg, "PROBE") == 0)
				conf.filter_pkt |= PKT_TYPE_PROBE;
			else if (strcmp(optarg, "ASSOC") == 0)
				conf.filter_pkt |= PKT_TYPE_ASSOC;
			else if (strcmp(optarg, "AUTH") == 0)
				conf.filter_pkt |= PKT_TYPE_AUTH;
			else if (strcmp(optarg, "RTS") == 0)
				conf.filter_pkt |= PKT_TYPE_RTSCTS;
			else if (strcmp(optarg, "ACK") == 0)
				conf.filter_pkt |= PKT_TYPE_ACK;
			else if (strcmp(optarg, "NULL") == 0)
				conf.filter_pkt |= PKT_TYPE_NULL;
			else if (strcmp(optarg, "QDATA") == 0)
				conf.filter_pkt |= PKT_TYPE_QDATA;
			else if (strcmp(optarg, "ARP") == 0)
				conf.filter_pkt |= PKT_TYPE_ARP;
			else if (strcmp(optarg, "IP") == 0)
				conf.filter_pkt |= PKT_TYPE_IP;
			else if (strcmp(optarg, "ICMP") == 0)
				conf.filter_pkt |= PKT_TYPE_ICMP;
			else if (strcmp(optarg, "UDP") == 0)
				conf.filter_pkt |= PKT_TYPE_UDP;
			else if (strcmp(optarg, "TCP") == 0)
				conf.filter_pkt |= PKT_TYPE_TCP;
			else if (strcmp(optarg, "OLSR") == 0)
				conf.filter_pkt |= PKT_TYPE_OLSR;
			else if (strcmp(optarg, "BATMAN") == 0)
				conf.filter_pkt |= PKT_TYPE_BATMAN;
			else if (strcmp(optarg, "MESHZ") == 0)
				conf.filter_pkt |= PKT_TYPE_MESHZ;
			/* if one of the individual subtype frames is selected we enable the general frame type */
			if (conf.filter_pkt & PKT_TYPE_ALL_MGMT)
				conf.filter_pkt |= PKT_TYPE_MGMT;
			if (conf.filter_pkt & PKT_TYPE_ALL_CTRL)
				conf.filter_pkt |= PKT_TYPE_CTRL;
			if (conf.filter_pkt & PKT_TYPE_ALL_DATA)
				conf.filter_pkt |= PKT_TYPE_DATA;
			break;
		case 'h':
		default:
			printf("\nUsage: %s [-h] [-q] [-P] [-i interface] [-t sec] [-d ms] [-b bytes]\n"
				"\t\t[-s] [-C] [-c IP] [-p port] [-o file] [-l file] [-v file] [-X[name]] [-x command]\n"
				"\t\t[-A strong|ssid] [-e MAC] [-f PKT_NAME] [-m MODE]\n\n"

				"General Options: Description (default value)\n"
				"  -h\t\tHelp\n"
				"  -q\t\tQuiet, no output\n"
				"  -P\t\tPrintlog\n"
				"  -i <intf>\tInterface name (wlan0)\n"
				"  -t <sec>\tNode timeout in seconds (60)\n"
				"  -d <ms>\tDisplay update interval in ms (100)\n"
				"  -b <bytes>\tReceive buffer size in bytes (not set)\n"

				"\nFeature Options:\n"
				"  -s\t\t(Poor mans) Spectrum analyzer mode\n\n"

				"  -C\t\tAllow client connection, server mode (off)\n"
				"  -c <IP>\tConnect to server with <IP>, client mode (off)\n"
				"  -p <port>\tPort number of server (4444)\n\n"

				"  -o <filename>\tWrite packet info into 'filename'\n\n"

				"  -l <filename>\tBedo log 'filename'\n\n"
				
				"  -v <filename>\tVirtual account 'filename'\n\n"

				"  -X[filename]\tAllow control socket on 'filename' (/tmp/horst)\n"
				"  -x <command>\tSend control command\n"
				"  -A <strong|ssid_xxx>\tAuto select channel matched with strongest wifi signal or assigned ssid\n"

				"\nFilter Options:\n"
				" Filters are generally 'positive' or 'inclusive' which means you define\n"
				" what you want to see, and everything else is getting filtered out.\n"
				" If a filter is not set it is inactive and nothing is filtered.\n"
				" All filter options can be specified multiple times.\n"
				"  -e <MAC>\tSource MAC addresses (xx:xx:xx:xx:xx:xx), up to 9 times\n"
				"  -f <PKT_NAME>\tFilter packet types\n"
				"  -m <MODE>\tOperating mode: AP|STA|ADH|PRB|WDS|UNKNOWN\n"
				"\n",
				argv[0]);
			exit(0);
			break;
		}
	}
}


void
init_spectrum(void)
{
	int i;

	for (i = 0; i < conf.num_channels && i < MAX_CHANNELS; i++) {
		list_head_init(&spectrum[i].nodes);
		ewma_init(&spectrum[i].signal_avg, 1024, 8);
		ewma_init(&spectrum[i].durations_avg, 1024, 8);
	}
}


int
main(int argc, char** argv)
{
	list_head_init(&essids.list);
	list_head_init(&nodes);

	get_options(argc, argv);

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
	signal(SIGHUP, sigint_handler);
	signal(SIGPIPE, sigpipe_handler);
	atexit(exit_handler);

	gettimeofday(&stats.stats_time, NULL);
	gettimeofday(&the_time, NULL);

	conf.channel_idx = -1;

	if (conf.allow_control) {
		printlog("Allowing control socket");
		control_init_pipe();
	}

	struct around_ap_info *aaps = NULL;
	if (conf.automatchchannel > 0) {
		if (searchAP(&aaps)) {
			int cur_chan = channel_get_config_chan();
			int chan;
			if (conf.automatchchannel == 1) 
				chan = best_chan_from_APInfo(aaps);
			if (conf.automatchchannel == 2)
				chan = chan_from_assignssid(aaps, conf.assign_ssid);
			printlog("best match channel:%d, current chan:%d", chan, cur_chan);
			if (chan > 0 && chan != cur_chan) {
				char cmd[32];
				sprintf(cmd, "channel=%d\n", chan);
				control_send_command(cmd);
			}
		}
	}

	freeAPs(aaps);
	if (conf.serveraddr)
		mon = net_open_client_socket(conf.serveraddr, conf.port);
	else {
		mon = open_packet_socket(conf.ifname, conf.recv_buffer_size);
		if (mon <= 0)
			err(1, "Couldn't open packet socket");

		conf.arphrd = device_get_hwinfo(mon, conf.ifname, conf.my_mac_addr);
		if (conf.arphrd != ARPHRD_IEEE80211_PRISM &&
		    conf.arphrd != ARPHRD_IEEE80211_RADIOTAP) {
			printf("You need to put your interface into monitor mode!\n");
			printf("(e.g. 'iw %s interface add mon0 type monitor' and 'horst -i mon0')\n", conf.ifname);
			exit(1);
		}

		channel_init();
		init_spectrum();
	}

	if (!conf.quiet && !DO_DEBUG)
		init_display();

	if (conf.dumpfile != NULL)
		dumpfile_open(conf.dumpfile);

	if (conf.bedologfile != NULL)
		bedo_logfile_open(conf.bedologfile);

	if (conf.viraccfile != NULL)
		virtual_accountfile_open(conf.viraccfile);
	
	bedo_log(BEDO_LOG_INFO, "conf.arphrd= %s\n", conf.arphrd == ARPHRD_IEEE80211_PRISM?"prism":"radiotap");

	if (!conf.serveraddr && conf.port && conf.allow_client)
		net_init_server_socket(conf.port);

	for ( /* ever */ ;;)
	{
		receive_any();
		gettimeofday(&the_time, NULL);
		timeout_nodes();

		if (!conf.serveraddr) { /* server */
			if (channel_auto_change()) {
				net_send_channel_config();
				update_spectrum_durations();
				if (!conf.quiet && !DO_DEBUG)
					update_display(NULL);
			}
		}
	}
	/* will never */
	return 0;
}


void
main_pause(int pause)
{
	conf.paused = pause;
	printlog(conf.paused ? "- PAUSED -" : "- RESUME -");
}


void
dumpfile_open(char* name)
{
	if (DF != NULL) {
		fclose(DF);
		DF = NULL;
	}

	if (name == NULL || strlen(name) == 0) {
		printlog("- Not writing outfile");
		conf.dumpfile = NULL;
		return;
	}

	conf.dumpfile = name;
	DF = fopen(conf.dumpfile, "w");
	if (DF == NULL)
		err(1, "Couldn't open dump file");

	printlog("- Writing to outfile %s", conf.dumpfile);
}

void 
bedo_logfile_open(char *name)
{
	if (BF != NULL) {
		fclose(BF);
		BF = NULL;
	}
	if (name == NULL || strlen(name) == 0) {
		printlog("- Not writing bedo logfile");
		conf.bedologfile = NULL;
		return;
	}

	conf.bedologfile = name;
	BF = fopen(name, "w");
	if (BF == NULL)
		err(1, "Couldn't open bedo log file");

	printlog("- Bedo log file %s", conf.bedologfile);
}

void 
virtual_accountfile_open(char *name)
{
	if (VF != NULL) {
		fclose(VF);
		VF = NULL;
	}
	if (name == NULL || strlen(name) == 0) {
		printlog("- Not writing virtual accountfile");
		conf.viraccfile = NULL;
		return;
	}

	conf.viraccfile = name;
	VF = fopen(name, "w");
	if (VF == NULL)
		err(1, "Couldn't open virtual accountfile");

	printlog("- virtual account file %s", conf.viraccfile);
}

#if 0
void print_rate_duration_table(void)
{
	int i;

	printf("LEN\t1M l\t1M s\t2M l\t2M s\t5.5M l\t5.5M s\t11M l\t11M s\t");
	printf("6M\t9\t12M\t18M\t24M\t36M\t48M\t54M\n");
	for (i=10; i<=2304; i+=10) {
		printf("%d:\t%d\t%d\t", i,
			ieee80211_frame_duration(PHY_FLAG_G, i, 10, 0, 0, IEEE80211_FTYPE_DATA, 0, 0),
			ieee80211_frame_duration(PHY_FLAG_G, i, 10, 1, 0, IEEE80211_FTYPE_DATA, 0, 0));
		printf("%d\t%d\t",
			ieee80211_frame_duration(PHY_FLAG_G, i, 20, 0, 0, IEEE80211_FTYPE_DATA, 0, 0),
			ieee80211_frame_duration(PHY_FLAG_G, i, 20, 1, 0, IEEE80211_FTYPE_DATA, 0, 0));
		printf("%d\t%d\t",
			ieee80211_frame_duration(PHY_FLAG_G, i, 55, 0, 0, IEEE80211_FTYPE_DATA, 0, 0),
			ieee80211_frame_duration(PHY_FLAG_G, i, 55, 1, 0, IEEE80211_FTYPE_DATA, 0, 0));
		printf("%d\t%d\t",
			ieee80211_frame_duration(PHY_FLAG_G, i, 110, 0, 0, IEEE80211_FTYPE_DATA, 0, 0),
			ieee80211_frame_duration(PHY_FLAG_G, i, 110, 1, 0, IEEE80211_FTYPE_DATA, 0, 0));

		printf("%d\t",
			ieee80211_frame_duration(PHY_FLAG_G, i, 60, 1, 0, IEEE80211_FTYPE_DATA, 0, 0));
		printf("%d\t",
			ieee80211_frame_duration(PHY_FLAG_G, i, 90, 1, 0, IEEE80211_FTYPE_DATA, 0, 0));
		printf("%d\t",
			ieee80211_frame_duration(PHY_FLAG_G, i, 120, 1, 0, IEEE80211_FTYPE_DATA, 0, 0)),
		printf("%d\t",
			ieee80211_frame_duration(PHY_FLAG_G, i, 180, 1, 0, IEEE80211_FTYPE_DATA, 0, 0)),
		printf("%d\t",
			ieee80211_frame_duration(PHY_FLAG_G, i, 240, 1, 0, IEEE80211_FTYPE_DATA, 0, 0)),
		printf("%d\t",
			ieee80211_frame_duration(PHY_FLAG_G, i, 360, 1, 0, IEEE80211_FTYPE_DATA, 0, 0));
		printf("%d\t",
			ieee80211_frame_duration(PHY_FLAG_G, i, 480, 1, 0, IEEE80211_FTYPE_DATA, 0, 0)),
		printf("%d\n",
			ieee80211_frame_duration(PHY_FLAG_G, i, 540, 1, 0, IEEE80211_FTYPE_DATA, 0, 0));
	}
}
#endif
