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
#include <pthread.h>
#include <signal.h>
#include <curl/curl.h>
#include <roxml.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
#include "hashmap.h"

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
	.capture		= 0,
	.handshake		= 0,
	.upload_interval	= 60,
	.avoid_repeat_time	= 10,
};

struct timeval the_time;
struct timeval the_dump_time;		/* dump mac address time */
struct timeval the_dumpsns_time;	/* dump sns address time */
struct timeval the_dumppcap_time;	/* dump packet(pcap) time */
struct timeval the_hashmac_time;	/* mac hashmap clear time*/
struct timeval the_readmac_time;	/* mac read clear time*/
struct timeval the_sendmac_time;	/* mac send clear time*/

struct type_content{
	int	type;
	int	length;
	char	buff[200];
};

int R = 1; /* if install in R0 assignment 0 to R; if install in R1 assignment 1 to R; 
	      if install in R3 assignment 3 to R       */
char card[] = "snsR1"; /* snsR0 snsR1 snsR3 represent different small card */

int type_1 = 1001;
int type_2 = 1002;
int id = 1;
int X = 12;
int Y = 13;
int sig = -111;
char essid[] = "hssid0";
char f = 'A';
static unsigned char macbuf[21];

struct sockaddr_in hostaddr;
int sockfd; /*UDP socket*/

int mon; /* monitoring socket */

// dump file
static FILE* DF = NULL;
// bedo buffer(debug) file
static FILE* BF = NULL;
// virtual account(SNS+IM)
static FILE* VF = NULL;
// capture packet
static FILE* PF = NULL; 

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

static pthread_t upload_mac_thd, upload_sns_thd, upload_pcap_thd;
static pthread_mutex_t t_sns_lock, t_mac_lock, t_pcap_lock; 
struct file_cache_info sns_cache_info = {
	.rfn = 0,
	.wfn = 0,
	.reading = false,
	.maxcount = 4,
};

struct file_cache_info mac_cache_info = {
	.rfn = 0,
	.wfn = 0,
	.reading = false,
	.maxcount = 4,
};

struct file_cache_info pcap_cache_info = {
	.rfn = 0,
	.wfn = 0,
	.reading = false,
	.maxcount = 4,
};


static const char *const_pcap_filename = "pcap";

/* bedo log level define */
static bedo_log_level gBedo_log_level = BEDO_LOG_INFO;

/* create mac hashmap */
hmap_t map;
macpkg *mpkghead = NULL;
macpkg *mpkgs = NULL;

/* ==========================================================================================*/
static bool virtual_acc_record(const char *type, const char *account, const char *mac, struct packet_info* p);

#define qq_flag_len		4
static bool 
valid_qq(const unsigned char* qqbuf, int nums, unsigned char* qq);

static unsigned char* 
mem_find(const unsigned char *buffer, int buflen, const unsigned char *findmem, int findlen);

static bool 
qq_filter(const unsigned char *buffer, int buflen, struct packet_info* p, const char* wlan_src, const char* wlan_dst);

static bool 
taobao_filter(const unsigned char *buffer, int buflen, struct packet_info* p, const char* wlan_src, const char* wlan_dst);

static bool 
weixin_filter(const unsigned char *buffer, int buflen, struct packet_info* p, const char* wlan_src, const char* wlan_dst);

static bool 
sinawb_filter(const unsigned char *buffer, int buflen, struct packet_info* p, const char* wlan_src, const char* wlan_dst);

/* search around AP */ 
static bool searchAP(struct around_ap_info **ppapinfo);
static int best_chan_from_APInfo(struct around_ap_info *apinfo);
static void freeAPs(struct around_ap_info *apinfo);

/* curl download file */
static bool curl_download(char *url, char *localfile);

static char*
des_type(struct packet_info* p);

static char *
mac_smbig_conversion(const char mac[18]);

static char *
mac_smbig_conversion_sh(const char *mac);

static char *
macbuf_smbig_conversion(const char mac[22]);

static char *
equipment_number_macbuf(void);

static void
dump_sns_cache(const char *type, const char *account, const char *mac, struct packet_info* p);

static void
dump_pcap_cache(char *p, int len);

static int
free_macpkg(void* data, void *arg);


/* ==========================================================================================*/
static int free_macpkg(void* data, void *arg) {
        macpkg *dat = (macpkg *) data;
        free(dat);
        return 0;
}

/* ==========================================================================================*/
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
				printlog("ap1 ssid=%s, signal=%d, channel=%d, encrypt=%s", apinfo->essid, 
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
			strncpy(apinfo->essid, pbuf, WLAN_MAX_SSID_LEN);		
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
		printlog("ap2 ssid=%s, signal=%d, channel=%d, encrypt=%s", apinfo->essid, 
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

/* curl get data callback */
long
curl_read_cb(void *data, int size, int nmemb, void *stream) 
{
	size_t sizes = size * nmemb;
	struct curl_readcb_info *pInfo = (struct curl_readcb_info*)stream;
	
	memcpy(pInfo->pMem+pInfo->size, data, sizes);
	pInfo->size += sizes;

	return sizes;
}

/* curl download file */
static bool 
curl_download(char *url, char *localfile)
{
	if (url == NULL || localfile == NULL)
		return false;

	bool bRet = false;
	CURL *curl = NULL;
	CURLcode code;
	long retcode = 0;
	char curl_err[128];
	struct curl_readcb_info readcb = {.pMem=NULL, .size=0};

	code = curl_global_init(CURL_GLOBAL_NOTHING);
	if (code != CURLE_OK) {
		printlog("Failed to global init nothing [%d]", code);
		return false;
	}
	
	curl = curl_easy_init();
	if (curl == NULL) {
		printlog("Failed in curl_easy_init");
		return false;
	}

	struct curl_slist *chunk = NULL;
	chunk = curl_slist_append(chunk, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
	chunk = curl_slist_append(chunk, "Accept-Encoding: gzip,deflate,sdch"); 
	chunk = curl_slist_append(chunk, "Accept-Language: zh-CN,zh;q=0.8,en;q=0.6");
	chunk = curl_slist_append(chunk, "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36");
	chunk = curl_slist_append(chunk, "Connection: Keep-Alive");  

	do 
	{
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
		code = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err);
		if (code != CURLE_OK) {
			printlog("Failed to set error buffer [%d]\n", code);
			break;
		}
		
		code = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);    
		if (code != CURLE_OK) {
			printlog( "Failed to set CURLOPT_HTTPHEADER [%s]\n",  curl_err);
			break;
		}

		code = curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60*5);
		if (code != CURLE_OK) {
			printlog( "Failed to set CURLOPT_TIMEOUT [%s]\n",  curl_err);
			break;
		}

		code = curl_easy_setopt(curl, CURLOPT_URL,  url);
		if (code != CURLE_OK) {
			printlog( "Failed to set CURLOPT_URL [%s]\n",  curl_err);
			break;
		}
		
		code = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_read_cb);
		if (code != CURLE_OK) {
			printlog( "Failed to set writer [%s]\n",  curl_err);
			break;
		}

		readcb.pMem = malloc(800*1024);
		readcb.size = 0;
		code = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readcb);
		if (code != CURLE_OK) {
			printlog( "Failed to set write data [%s]\n",  curl_err);
			break;
		}

		code = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
		if (code != CURLE_OK) {
			printlog( "Failed to set redirect option [%s]\n",  curl_err);
			break;
		}

		code = curl_easy_perform(curl);
		if (code != CURLE_OK) {
			printlog("Failed to curl_easy_perform [%s]", curl_err);
			break;
		}	
		
		code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &retcode);
		if (code != CURLE_OK) {
			printlog("Failed to curl_easy_perform [%s]", curl_err);
			break;
		}
		if (retcode != 200) {
			printlog("Failed to curl_easy_perform , retcode=%d", retcode);
			break;
		}
		
		printlog("curl download return 200");
		bRet = true;
	} while (false);
	
	curl_slist_free_all(chunk);
	curl_easy_cleanup(curl);
	curl_global_cleanup();
	
	if (bRet) {
		FILE *fp = fopen(localfile, "w+b");
		if (fp == NULL) {
			printlog("Failed in curl_download, open file %s error", localfile);
			bRet = false;
		}
		else {
			fwrite(readcb.pMem, 1, readcb.size, fp);
			fflush(fp);
			fclose(fp);	
		}
	}

	if (readcb.pMem)
		free(readcb.pMem);

	return  bRet;
}

/*according to upload response to decide wether do upgrade*/
static void
upload_mac_callback()
{
	char *paddr = NULL;
	char *ptmp, *action=NULL, *url=NULL;
	int len, size;
	node_t *vernode, *item;
	bool bhandle = false;
 
	/* response will return to file /tmp/upmac_resp, pls refer to upload.sh  */
	int fd = open("/tmp/upmac_resp", O_RDONLY);
	if (fd == -1)
		return;
	
	size = fdsize(fd);	
	if (size <= 0) {
		close(fd);	
		return;
	}
	
	paddr = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (paddr == MAP_FAILED) {
		close(fd);
		return;
	}	
	
	ptmp = strstr(paddr, "200 OK");
	if (ptmp == NULL) {
		close(fd);
		return;
	}

	ptmp = strstr(paddr, "<?xml");
	if (ptmp == NULL) {
		close(fd);
		return;
	}
	
	node_t *root = roxml_load_buf(ptmp);
	if (root == NULL) {
		close(fd);
		return;
	}
	
	vernode = roxml_get_chld(root, "version", 0);
	if (vernode == NULL) {
		roxml_close(root);	
		close(fd);
		return;
	}
	
	item = roxml_get_chld(vernode, "action", 0);
	if (item) {
		action = roxml_get_content(item, NULL, 0, &len);	
		printlog("action=%s", action);
	}

	item = roxml_get_chld(vernode, "url", 0);
	if (item) {
		url = roxml_get_content(item, NULL, 0, &len);
		printlog("action=%s", url);
	}

	if (0 == strcmp(action, "force") && url) {
		bhandle = true;
	}	
	
	if (bhandle) {
		/* download ipk */
		char *ipk = "/tmp/horst.ipk";
		bool db = curl_download(url, ipk);
		printlog("download sucess = %d", db);
		if (db) {
			char cmd[256];
			sprintf(cmd, "/opt/scanner/upgrade.sh %s", ipk);
			system(cmd);
		}
	}

	if (action)
		roxml_release(action);
	if (url)
		roxml_release(url);
	roxml_close(root);
	close(fd);
	//unlink("/tmp/upmac_resp");
		
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
	static unsigned char qq[20];
	bool ret = false;

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
					printlog("printlog QQ=%s, MAC=%s", qq, bindmac);
					bedo_log(BEDO_LOG_INFO,"log QQ=%s, MAC=%s", qq, bindmac);
					dump_sns_cache("QQ", qq, bindmac, p);
					ret = true;
				}
			}
			nums=0;
		}
	}	
	
	return ret;
}

static const char *s_host = "Host:", *s_http_flag = "HTTP/1.";
static const unsigned char s_sep[] = {0x0d, 0x0a};
 
static bool 
taobao_filter(const unsigned char *buffer, int buflen, struct packet_info* p, const char* wlan_src, const char* wlan_dst)
{
	static const char *domain = "taobao.com"; 
	const char *host = s_host;
	static const char *taobao_flags[] = {"_w_tb_nick=", "_nk_=", "lgc=", "tracknick="};
	static const char *taobao_endch = ";";
	const unsigned char *sep = s_sep;
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
		dump_sns_cache("TAOBAO", account, bindmac, p);
		break;
	}

	if (strlen(account) == 0)
		return false;

	return true;
}

static bool 
weixin_filter(const unsigned char *buffer, int buflen, struct packet_info* p, const char* wlan_src, const char* wlan_dst)
{
	static const char *post_domain = "short.weixin.qq.com";
	static const char *get_domain = "weixin.qq.com";
	static const char *refer = "Referer:"; 
	const char *host = s_host, *http_flag = s_http_flag;
	const unsigned char *sep = s_sep;
	const unsigned char body_start[] = {0x0d, 0x0a, 0x0d, 0x0a};
	const char *get = "GET ", *post = "POST ";	

	int i, len, remain, action = 0;
	unsigned char *pt, *pt1, *pt2;
	char account[128];

	if (buffer == NULL || buflen == 0)
		return false;

	// to-do: parse should start after TCP header 
	remain = buflen;
	pt = mem_find(buffer, buflen, http_flag, strlen(http_flag));
	if (pt == NULL)
		return false;

	pt = mem_find(buffer, buflen, post, strlen(post));	
	if (pt != NULL)
		action = 1; 		// action = POST
	else { 
		pt = mem_find(buffer, buflen, get, strlen(get));
		if (pt != NULL)
			action = 0;	// action = GET
		else
			return false;
	}
	pt = mem_find(buffer, buflen, host, strlen(host));
	if (pt == NULL) 
		return false;

	pt = pt + strlen(host);
	remain = buflen - (pt - buffer);
	pt1 = mem_find(pt, remain, sep, 2);
	if (pt1 == NULL)
		return false;
	//printlog("0d0a find");

	len = pt1 - pt + 2;
	pt1 = mem_find(pt, len, get_domain, strlen(get_domain));
	if (pt1 == NULL) {				// is not weixin domain
		pt = mem_find(buffer, buflen, refer, strlen(refer));
		if (pt == NULL)
			return false;
		pt = pt + strlen(refer);
		remain = buflen - (pt - buffer);
		pt1 = mem_find(pt, remain, sep, 2);
		if (pt1 == NULL)
			return false;
		len = pt1 - pt + 2;
		pt1 = mem_find(pt, len, get_domain, strlen(get_domain));
		if (pt1 == NULL)
			return false;
		len = pt1 - pt;
	}	
	pt = pt + len;
	remain = remain - len;
	//printlog("domain find, aciton=%d, domain=%s", action, pt1);
	bedo_log(BEDO_LOG_INFO,"domain find, domain=%s", pt1);
	
	char *bindmac = wlan_src;
	if (p->wlan_mode == WLAN_MODE_AP)
		bindmac = wlan_dst;
	
	if (action == 1) { // POST
		pt1 = mem_find(pt, remain, body_start, sizeof(body_start));
		if (pt1 == NULL)
			return false;
		pt1 = pt1 + sizeof(body_start) + 6;  // 6 bytes = 2bytes(magic) + 4bytes(version)
		unsigned int i_uin = 0;
		i_uin = *((unsigned int *)pt1);
		sprintf(account, "%u", i_uin);		
		printlog("weixin=%s, MAC=%s", account, bindmac);
		dump_sns_cache("WEIXIN", account, bindmac, p);
	}
	else {
		char *uin_flag = "uin=";
		pt1 = mem_find(pt, remain, uin_flag, strlen(uin_flag));
		if (pt1 == NULL)
			return false;
		pt1 = pt1 + strlen(uin_flag);
		pt2 = mem_find(pt1, buflen-(pt1-buffer), "&", 1);
		if (pt2 == NULL) {
			pt2 = mem_find(pt, remain, sep, strlen(sep));
			if (pt2 == NULL)
				return false;
		}
		len = pt2 - pt1;
		strncpy(account, pt1, len);
		printlog("Get weixin=%s, MAC=%s", account, bindmac);
		dump_sns_cache("WEIXIN", account, bindmac, p);
	}
	

	return true;
}


static bool 
sinawb_filter(const unsigned char *buffer, int buflen, struct packet_info* p, const char* wlan_src, const char* wlan_dst) 
{
	static const char *domain = "wbapp.mobile.sina.cn";
	static const char *domain1 = "sdkapp.mobile.sina.cn";
	static const char *domain2 = "sinaimg.cn";
	
	const char *host = s_host, *http_flag = s_http_flag;
	const unsigned char *sep = s_sep;
	const unsigned char body_start[] = {0x0d, 0x0a, 0x0d, 0x0a};
	const char *get = "GET ", *post = "POST ";	

	int i, len, remain, action = 0;
	unsigned char *pt, *pt1, *pt2;
	char account[128], *tmp;
	if (buffer == NULL || buflen == 0)
		return false;

	// to-do: parse should start after TCP header 
	remain = buflen;
	pt = mem_find(buffer, buflen, http_flag, strlen(http_flag));
	if (pt == NULL)
		return false;

	pt = mem_find(buffer, buflen, post, strlen(post));	
	if (pt != NULL)
		action = 1; 		// action = POST
	else { 
		pt = mem_find(buffer, buflen, get, strlen(get));
		if (pt != NULL)
			action = 0;	// action = GET
		else
			return false;
	}

	pt = mem_find(buffer, buflen, host, strlen(host));
	if (pt == NULL) 
		return false;

	pt = pt + strlen(host);
	remain = buflen - (pt - buffer);
	pt1 = mem_find(pt, remain, sep, 2);
	if (pt1 == NULL)
		return false;
	//printlog("0d0a find");

	len = pt1 - pt + 2;
	tmp = (char*)malloc(len+1);
	memcpy(tmp, pt, len);
	*(tmp+len) = 0;
	printlog("domain find, aciton=%d, domain=%s", action, tmp);
	bedo_log(BEDO_LOG_INFO,"domain find, domain=%s", tmp);
	free(tmp);
	
	pt1 = mem_find(pt, len, domain, strlen(domain));
	if (pt1 == NULL) {
		pt1 = mem_find(pt, len, domain1, strlen(domain1));
	}
	if (pt1 == NULL) {
		pt1 = mem_find(pt, len, domain2, strlen(domain2));
	}
	if (pt1 == NULL)
		return false;
 
	char *bindmac = wlan_src;
	if (p->wlan_mode == WLAN_MODE_AP)
		bindmac = wlan_dst;
	
	char *uid_flag = "uid=";
	char *log_uid_flag = "X-Log-Uid: ";
	bool is_log = true;
	pt = buffer;
	remain = buflen;
	pt1 = mem_find(pt, remain, log_uid_flag, strlen(log_uid_flag));
	if (pt1 == NULL) {
		is_log = false;
		pt1 = mem_find(pt, remain, uid_flag, strlen(uid_flag));
		if (pt1 == NULL)
			return false;
	}
	//printlog("%s is found", is_log?"x-log-uid":"uid=");
	if (false == is_log) {
		pt1 = pt1 + strlen(uid_flag);
	
		pt2 = mem_find(pt1, buflen-(pt1-buffer), "&", 1);
		if (pt2 == NULL) {
			pt2 = mem_find(pt, remain, sep, strlen(sep));
			if (pt2 == NULL)
				return false;
		}
	}
	else {
		pt1 = pt1 + strlen(log_uid_flag);	
		pt2 = mem_find(pt1, buflen-(pt1-buffer), sep, strlen(sep));
		if (pt2 == NULL)
			return false;
	}
	len = pt2 - pt1;
	strncpy(account, pt1, len);
	account[len] = 0x0;
	printlog("Get WBSINA=%s, MAC=%s", account, bindmac);
	dump_sns_cache("WBSINA", account, bindmac, p);
	
	return true;
}

static bool
imeiimsi_filter(const unsigned char *buffer, int buflen, struct packet_info* p, const char* wlan_src, const char* wlan_dst)
{
	static const char *domains[] ={ "api.m.taobao.com",
					"statis.api.3g.youku.com",
					"wifiapi02.51y5.net",
					"api.app.i.sogou.com",
					"wspeed.qq.com",
					"log.web.fanxing.com",
					"m.api.zhe800.com"
		};
	static const char *flags[] = {"imei=", "imsi="};
	static const char *endch = "&";

	const char *host = s_host, *http_flag = s_http_flag;
	const unsigned char *sep = s_sep;
	const unsigned char body_start[] = {0x0d, 0x0a, 0x0d, 0x0a};
	const char *get = "GET ", *post = "POST ";

	int i, len, remain, action = 0;
	unsigned char *pt, *pt1, *pt2;
	char account[128], *tmp;
	if (buffer == NULL || buflen == 0)
		return false;

	// to-do: parse should start after TCP header 
	remain = buflen;
	pt = mem_find(buffer, buflen, http_flag, strlen(http_flag));
	if (pt == NULL)
		return false;

	printlog("url: %s", buffer);
	pt = mem_find(buffer, buflen, post, strlen(post));
	if (pt != NULL)
		action = 1;		// action = POST
	else {
		pt = mem_find(buffer, buflen, get, strlen(get));
		if (pt != NULL)
			action = 0;	// action = GET
		else
			return false;
	}

	pt = mem_find(buffer, buflen, host, strlen(host));
	if (pt == NULL)
		return false;

	pt = pt + strlen(host);
	remain = buflen - (pt - buffer);
	pt1 = mem_find(pt, remain, sep, 2);
	if (pt1 == NULL)
		return false;
	printlog("imei 0d0a find");

	len = pt1 - pt + 2;
	tmp = (char*)malloc(len+1);
	memcpy(tmp, pt, len);
	*(tmp+len) = 0;
	//bedo_log(BEDO_LOG_INFO,"domain find, domain=%s", tmp);
	printlog("domain find, aciton=%d, domain=%s", action, tmp);
	free(tmp);

	printlog("domains count: %d, flags count %d", sizeof(domains)/sizeof(char*), sizeof(flags)/sizeof(char*));
	for (i=0; i<sizeof(domains)/sizeof(char*); i++) {
		const char *domain = domains[i];
		printlog("search domain: %s", domain);
		pt1 = mem_find(pt, len, domain, strlen(domain));
		if (pt1 != NULL)
			break;
	}
	if (pt1 == NULL)
		return false;
	char *bindmac = wlan_src;
	if (p->wlan_mode == WLAN_MODE_AP)
		bindmac = wlan_dst;


	memset(account, 0, 128);
	for (i=0; i<sizeof(flags)/sizeof(char*); i++) {
		const char *flag = flags[i];

		pt1 = mem_find(pt, remain, flag, strlen(flag));
		if (pt1 == NULL)
			continue;
		printlog("find imei start flag");

		pt1 = pt1 + strlen(flag);
		pt2 = mem_find(pt1, buflen-(pt1-buffer), endch, 1);
		if (pt2 == NULL || (pt2-pt1)>=128)
			continue;
		printlog("find imei end flag");

		memset(account, 0, 128);
		memcpy(account, pt1, pt2-pt1);

		//bedo_log(BEDO_LOG_INFO, "%s=%s, MAC=%s",flags[i], account, bindmac);
		printlog("%s=%s, MAC=%s",flags[i], account, bindmac);
		dump_sns_cache(flags[i], account, bindmac, p);
		break;
	}

	if (strlen(account) == 0)
		return false;

	return true;
}


static bool virtual_acc_record(const char *type, const char *account, const char *mac, struct packet_info* p)
{
	if (VF == NULL)
		return false;

	if (type == NULL || account == NULL || mac == NULL)
		return false;

	struct timeval tv;
	char buf[200];
	
	memset(buf, 0, 200);
	gettimeofday(&tv, NULL);
	sprintf(buf, "%d, %s, %s, %s, %s", tv.tv_sec, type, mac_smbig_conversion(mac), account, get_packet_type_name(p->wlan_type));
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
	if (NULL == p)
		return;

	fprintf(DF, "%d, ", the_time.tv_sec);
	fprintf(DF, "%s, %s, ",
		get_packet_type_name(p->wlan_type), mac_smbig_conversion(ether_sprintf(p->wlan_src)));
	fprintf(DF, "%s, ", mac_smbig_conversion(ether_sprintf(p->wlan_dst)));
	fprintf(DF, "%s, %d", p->wlan_essid,  p->phy_signal);
	
	/*fprintf(DF, ", mode=%d, channel=%d, wep=%d, wpa=%d, rsn=%d",
		p->wlan_mode, p->wlan_channel,
		p->wlan_wep, p->wlan_wpa, p->wlan_rsn);
	*/
	fprintf(DF, ", %d, %d, %d, %d, %d",
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
	if (BF == NULL && PF == NULL)
		return;

	int i, j;
	time_t timer;
	struct tm *t_tm;
	char cur_t[128];

	timer = time(NULL);
	t_tm = localtime(&timer);
	memset(cur_t, 0, 128);
	sprintf(cur_t, "%4d-%02d-%02d %02d:%02d:%02d", t_tm->tm_year+1900, t_tm->tm_mon+1, t_tm->tm_mday, t_tm->tm_hour, t_tm->tm_min, t_tm->tm_sec);
	if (BF != NULL) {
		fprintf(BF, "---%s---", cur_t);

		int line = lnlen;
		char buf[line];
		for (i = 0; i < len; i++) {
			if ((i % lnlen) == 0 ) {
				if (addbin && i > 0) {
					fprintf(BF, "    ");
					for (j=0; j<line; j++) {
						char ch = *(p+i-line+j);
						if (ch == 0x0d || ch == 0x0a)
							ch = 0x2e;
						buf[j] = ch;
					}
					fwrite(buf, line, 1, BF);
				}
				fprintf(BF, "\n");
			}
			fprintf(BF ,"%02x", *((unsigned char*)(p+i)));
		}
		if (addbin) {
			line = len%lnlen;
			if (line == 0)
				line = lnlen;
	
			fprintf(BF, "    ");
			for (j=0; j<line; j++) {
				char ch = *(p+len-(line-j));
				if (ch == 0x0d || ch == 0x0a)
					ch = 0x2e;
				buf[j] = ch;
			}
			fwrite(buf, line, 1, BF);
		}
		fprintf(BF, "\n");
	}
	
	if (PF != NULL) 
		dump_pcap_cache(p, len);
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
		dump_mac_cache(p);	
	
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

static char *
mac_smbig_conversion(const char mac[18])
{
	int i = 0;
	static unsigned char wlan_mac[18];
	
	memset(wlan_mac, 0, 18);
	memcpy(wlan_mac, mac, 17);
	for (i; i < 17; i++) {
		if (wlan_mac[i] >= 'a' && wlan_mac[i] <= 'z')
			wlan_mac[i] -= 32;
	}
	return wlan_mac;
}

static void
send_collect_ap_info(struct packet_info* p)
{
	char buf[200];
	memset(buf, 0 , 200);
	struct type_content t_content;
	struct timeval tv;
	gettimeofday(&tv, NULL);

	if(p != 0 && (strcmp(get_packet_type_name(p->wlan_type), "PROBRP") == 0 || strcmp(get_packet_type_name(p->wlan_type), "BEACON") == 0))
	{
		sprintf(buf, "%s\t%s\t%d\t%s\t%d\t%d\t%d\t%d\t%c\t%s\t%c\t%c\t%s\r\n", mac_smbig_conversion(ether_sprintf(p->wlan_src)), p->wlan_essid, 
				p->wlan_channel, des_type(p), tv.tv_sec, p->phy_signal, X, Y, f, macbuf, f, f, card); 

		struct type_content t_content;
		bzero(t_content.buff, sizeof(t_content.buff));
		t_content.type = type_2;
		t_content.length = strlen(buf);
		strcpy(t_content.buff, buf);
		sendto(sockfd, &t_content, sizeof(t_content), 0, (struct sockaddr *)&hostaddr, sizeof(hostaddr));

	}
}

static void
local_receive_packet(int fd, unsigned char* buffer, size_t bufsize)
{
	int len;
	struct packet_info p;
	const unsigned char kLxfMac[] = {0xc4, 0x6a, 0xb7, 0xd4, 0xeb, 0xa9};
	const unsigned char kMyMac[] = {0x28, 0xe0, 0x2c, 0xc7, 0x18, 0xa0};
	unsigned char wlan_src[18],  wlan_dst[18];

	len = recv_packet(fd, buffer, bufsize);
	//bedo_log(BEDO_LOG_INFO, "recv_packet len=%d", len);
#if DO_DEBUG
	dump_packet(buffer, len);
#endif
	memset(&p, 0, sizeof(p));

	if (!parse_packet(buffer, len, &p)) {
		DEBUG("parsing failed\n");
		return;
	}

	//send_collect_ap_info(&p);

	handle_packet(&p);

	memset(wlan_src, 0, 18);
	memset(wlan_dst, 0, 18);
	memcpy(wlan_src, ether_sprintf(p.wlan_src), 17);
	memcpy(wlan_dst, ether_sprintf(p.wlan_dst), 17);
	/*
	bedo_log(BEDO_LOG_INFO, "wlan_src:%s, wlan_dst:%s, mymac=%s", wlan_src, 
		p.wlan_dst, ether_sprintf(kMyMac));
	*/ 
	/*if ((memcmp(p.wlan_src, kMyMac, 6)==0) 
	|| (memcmp(p.wlan_dst, kMyMac, 6) == 0) 
	|| (memcmp(p.wlan_src, kLxfMac, 6)==0) 
	|| (memcmp(p.wlan_dst, kLxfMac, 6) ==0)) {	
		//bedo_log(BEDO_LOG_INFO, "same wlan_src:%s, wlan_dst:%s", wlan_src, wlan_dst);
		handle_buffer(buffer, len, 32, true);
		if ((p.pkt_types&PKT_TYPE_HANDSHAKE) == PKT_TYPE_HANDSHAKE)
			printlog("packet is a handshake");
	}
	*/
#if 0
	if ((p.pkt_types&PKT_TYPE_AUTH) == PKT_TYPE_AUTH) { /*send 4 ways handshake to server */
		handle_buffer(buffer, len, 32, true);
		printlog("packet is a type_auth");
	}
#endif
	bool capture = false;
	if (conf.capture==1 &&  conf.handshake == 1) {  /* capture handshake*/
		if ( (p.wlan_mode == WLAN_MODE_STA)   /* only capture send out packet */
                    ||((p.pkt_types&PKT_TYPE_HANDSHAKE) == PKT_TYPE_HANDSHAKE) )
			capture = true;
	}
	else { /* don't require handshake */ 
		if ( ((p.pkt_types&PKT_TYPE_DATA)==PKT_TYPE_DATA) 
		     && (((p.pkt_types&PKT_TYPE_TCP) == PKT_TYPE_TCP)||((p.pkt_types&PKT_TYPE_UDP)== PKT_TYPE_UDP))
	             /*&& ((memcmp(p.wlan_src, kMyMac, 6)==0) || (memcmp(p.wlan_dst, kMyMac, 6) == 0))*/
		     && (p.wlan_mode == WLAN_MODE_STA) /*only capture send out packet*/ )
		capture = true;
	}

	if (capture) {	
		handle_buffer(buffer, len, 32, true);
	}
	if (conf.viraccfile != NULL) {	
		//if ((p.pkt_types&PKT_TYPE_HANDSHAKE) == PKT_TYPE_HANDSHAKE)
		//	printlog("packet is a handshake");
		

		//printlog("pkt_types=%08x, pkt_types&PKT_TYPE_TCP=%08x, wlan_src:%s, wlan_dst:%s",
		//	  p.pkt_types, p.pkt_types&PKT_TYPE_TCP, wlan_src, wlan_dst);
	
		bedo_log(BEDO_LOG_INFO, "pkt_types=%08x, pkt_types&PKT_TYPE_TCP=%08x, wlan_src:%s, wlan_dst:%s",
			  p.pkt_types, p.pkt_types&PKT_TYPE_TCP, wlan_src, wlan_dst);

		imeiimsi_filter(buffer, len, &p, wlan_src, wlan_dst);
		if (taobao_filter(buffer, len, &p, wlan_src, wlan_dst)) 
			return;
		if (weixin_filter(buffer, len, &p, wlan_src, wlan_dst))
			return;
		if (sinawb_filter(buffer, len, &p, wlan_src, wlan_dst))
			return;
		if (qq_filter(buffer, len, &p, wlan_src, wlan_dst))
			return;
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
	if (PF != NULL) {
		fclose(PF);
		PF = NULL;
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

	while((c = getopt(argc, argv, "hqsCPgi:I:t:c:p:e:f:d:o:b:X::x:m:u:U:a:l:n:v:A:")) > 0) {
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
		case 'I':
			conf.upload_interval = atoi(optarg);
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
		case 'a':
			conf.avoid_repeat_time = atoi(optarg);
			break;
		case 'l':
			conf.bedologfile = optarg;
			break;
		case 'n':
			conf.channel_ini = atoi(optarg);
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
		case 'g':
			conf.capture = 1;
			break;
		case 'H':
			conf.handshake = 1;
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
			printf("\nUsage: %s [-h] [-q] [-P] [-i interface] [-I sec] [-t sec] [-d ms] [-b bytes]\n"
				"\t\t[-s] [-C] [-c IP] [-p port] [-o file] [-l file] [-v file] [-X[name]] [-x command]\n"
				"\t\t[-A strong|ssid] [-e MAC] [-f PKT_NAME] [-m MODE] [-g][-H]\n\n"

				"General Options: Description (default value)\n"
				"  -h\t\tHelp\n"
				"  -q\t\tQuiet, no output\n"
				"  -P\t\tPrintlog(0)\n"
				"  -i <intf>\tInterface name (wlan0)\n"
				"  -I <sec>\tupload in seconds(60)\n"
				"  -t <sec>\tNode timeout in seconds (60)\n"
				"  -d <ms>\tDisplay update interval in ms (100)\n"
				"  -b <bytes>\tReceive buffer size in bytes (not set)\n"
				"  -a <sec>\tavoid repeat(10)\n "
				"  -g\t\tCapture tcp packet(send) and send to server(.pcap format)\n"
                                "  -H\t\tfollowing with -g, whether capture Handshake\n" 

				"\nFeature Options:\n"
				"  -s\t\t(Poor mans) Spectrum analyzer mode\n\n"

				"  -C\t\tAllow client connection, server mode (off)\n"
				"  -c <IP>\tConnect to server with <IP>, client mode (off)\n"
				"  -p <port>\tPort number of server (4444)\n\n"

				"  -o <filename>\tWrite packet info into 'filename'\n\n"

				"  -l <filename>\tBedo log 'filename'\n\n"
			    	"  -n <channel>\tset channel idx\n\n"	
				"  -v <filename>\tVirtual account 'filename'\n\n"

				"  -X[filename]\tAllow control socket on 'filename' (/tmp/mty)\n"
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

static char *
des_type(struct packet_info* p)
{
	char* encryption;
	if (p->wlan_wep == 1 && p->wlan_wpa == 0 && p->wlan_rsn == 0)
		encryption = "01";	//encryption = "WEP";
	else if (p->wlan_wep == 1 && p->wlan_wpa == 0 && p->wlan_rsn == 1)
		encryption = "03";	//encryption = "WPA2";
	else if (p->wlan_wep == 1 && p->wlan_wpa == 1 && p->wlan_rsn == 0)
		encryption = "02";	//encryption = "WPA";
	else 
		encryption = "99";	//encryption = "Other";

	return encryption;
}

/* Interception of MAC before 6 */
static char *
ether_printf(const char *mac)
{
	int i, j;
	char ch = '-';
	static unsigned char w_mac[9];
	memset(w_mac, 0, 9);
	memcpy(w_mac, mac, 8);
	static unsigned char w_mac1[7];	
	memset(w_mac1, 0, 7);

	for(j = i = 0; j < 8; j++) {
		if(w_mac[j] != ch) {
			w_mac[i++] = w_mac[j];
		}
	}
	memcpy(w_mac1, w_mac, 6);
	
	return w_mac1;
}

/* Lowercase converted to uppercase */
static char *
mac_smbig_conversion_sh(const char *mac)
{
	int i = 0;
	static unsigned char wlan_mac[7];
	memset(wlan_mac, 0, 7);
	memcpy(wlan_mac, mac, 6);
	for (i; i < 6; i++) {
		if (wlan_mac[i] >= 'a' && wlan_mac[i] <= 'z')
			wlan_mac[i] -= 32;
	}
	return wlan_mac;
}

/* Mobile phone brand match */
static char *
phone_brand(const char *mac) {
	static char *brand, *pbuf, *other = "other";
	static char brand_mac[7], buf[256];
	memset(buf, 0, sizeof(buf));
	memset(brand_mac, 0, 7);

	memcpy(brand_mac, mac_smbig_conversion_sh(ether_printf(mac)), 6);
	brand = brand_mac;
	//printf("brand:%s\n", brand);

	FILE *fp = fopen("/opt/brand.txt", "r");
	if (fp == NULL) {
		printf("Open brand.txt failed\n");
	}
	else{
		//printf("Open brand.txt success!\n");
	}

	while(fgets(buf, sizeof(buf), fp)) {
		pbuf = buf;
		if (NULL != strstr(pbuf, brand)) {
			fclose(fp);
			strsep(&pbuf, "	");
			pbuf = trim(pbuf);
			//printf("pbuf:%s\n", pbuf);
			return pbuf;
		}
	}
	fclose(fp);
	return other;
}

void
dump_mac_cache(struct packet_info* p)
{
	int cs = 0;
	int ret;
	int w = 0;
	if (DF == NULL)
		return;
	
	/* if time expired or cache file size more than 200K */ 
	if (the_time.tv_sec - the_dump_time.tv_sec > conf.upload_interval 
	    || (cs = ffsize(DF)) > 200*1024 ) {
		dumpfile_open(conf.dumpfile);
	}
	if (p == NULL)
		return;

	//static char wlansrc[18];
	//static char wlandst[18];
	char buf[200];
	memset(buf, 0 , 200);
	struct type_content t_content;

	if (the_time.tv_sec - the_hashmac_time.tv_sec > conf.avoid_repeat_time) {
		printlog("hashmap_size: %d", hashmap_size(map));
 		printlog("mpkgs value is: %d, mpkghead valus: %d", mpkgs, mpkghead);	
		/**
		  restor hashmap
		*/
		hashmap_clearall(map);
		mpkgs = mpkghead;			
		gettimeofday(&the_hashmac_time, NULL);
 		printlog("mpkgs memory pools resert.");	
		printlog("hashmap_size: %d", hashmap_size(map));
	}	
	//safe macpkg point.
	if (hashmap_size(map) >= MAPPKG_INITIAL_SIZE)
		mpkgs = mpkghead;

	memset(mpkgs, 0, sizeof(macpkg));
	
	memcpy(p->wlan_src, mpkgs->wlan_src, MAC_LEN);	
	ret = hashmap_put(map, ether_sprintf(p->wlan_src), mpkgs);
	if (ret == HMAP_S_OK) {
		mpkgs = mpkgs + 1;

#if 0
		gettimeofday(&the_time, NULL);
		sprintf(buf, "%s\t%s\t%s\t%d\t%d\t%c\t%c\t%s\t%s\t%d\t%s\t%d\t%d\t%c\t%s\t%c\t%c\t%s\r\n", mac_smbig_conversion(ether_sprintf(p->wlan_src)), 
				phone_brand(ether_sprintf(p->wlan_src)), essid, the_time.tv_sec, sig, id, f, p->wlan_essid, mac_smbig_conversion(ether_sprintf(p->wlan_dst)), 
				p->wlan_channel, des_type(p), X, Y, f, macbuf, f, f, card);
		t_content.type = type_1;
		t_content.length = strlen(buf);
		strcpy(t_content.buff, buf);
		sendto(sockfd, &t_content, sizeof(t_content), 0, (struct sockaddr *)&hostaddr, sizeof(hostaddr));

		write_to_file(p);	
#endif
		w = 1;
		printlog("debug put  src_mac: %s", ether_sprintf(p->wlan_src));
	}
	
	ret = hashmap_put(map, ether_sprintf(p->wlan_dst), mpkgs);
	if (ret == HMAP_S_OK) {
                mpkgs = mpkgs + 1;
                if(w == 0) {
#if 0
			write_to_file(p);

			gettimeofday(&the_time, NULL);
			sprintf(buf, "%s\t%s\t%s\t%d\t%d\t%c\t%c\t%s\t%s\t%d\t%s\t%d\t%d\t%c\t%s\t%c\t%c\t%s\r\n", mac_smbig_conversion(ether_sprintf(p->wlan_src)), 
				phone_brand(ether_sprintf(p->wlan_src)), essid, the_time.tv_sec, sig, id, f, p->wlan_essid, mac_smbig_conversion(ether_sprintf(p->wlan_dst)), 
				p->wlan_channel, des_type(p), X, Y, f, macbuf, f, f, card);
			t_content.type = type_1;
			t_content.length = strlen(buf);
			strcpy(t_content.buff, buf);
			sendto(sockfd, &t_content, sizeof(t_content), 0, (struct sockaddr *)&hostaddr, sizeof(hostaddr));
#endif
		}
		printlog("debug put  dst_mac: %s", ether_sprintf(p->wlan_dst));
	}
}


void *
upload_mac_fun(void *arg)
{
	printlog("upload mac file thread begin....");
	int r, w;
	char cachefile[128];
	
	for (;;) {		
		pthread_mutex_lock(&t_mac_lock);
		
		r = mac_cache_info.rfn;
		w = mac_cache_info.wfn;

		memset(cachefile, 0, 128);
	
		/* has file to upload */ 
		if (w > (r+1))
			r++;
		else if (w < r && (w+mac_cache_info.maxcount) > (r+1)) {
			r++; 			
		}
		
		if (mac_cache_info.rfn != r) {
			if (r > mac_cache_info.maxcount)		/* circle pointer */
				r = 1;
			if (NULL != conf.dumpfile) {
				sprintf(cachefile, "%s_%d",  conf.dumpfile, r);
				printlog("mac cache = %s", cachefile);	
			}
			if (strlen(cachefile) && 0 == access(cachefile, R_OK)) {
				mac_cache_info.reading = true;
				mac_cache_info.rfn = r;	
			}
		}

		pthread_mutex_unlock(&t_mac_lock);

		/* now read out */
		if (mac_cache_info.reading == true && fpsize(cachefile) > 0) {
			printlog("sending mac data...");
			
			char *cmd = malloc(512);
			sprintf(cmd, "/opt/scanner/upload.sh mac %s %s", cachefile, VERSION);	
			system(cmd);
			free(cmd);					
			printlog("sending mac data finished");
			
			/* system upgrade according to response */
			upload_mac_callback();

		}
		else {
			printlog("no mac data to send in this time");
		}

		mac_cache_info.reading = false;	
		
		sleep(2);
	}

	return ((void*)0);
}

/* -------------------------------------------------------------------------------------------*/
/* sns cache handle */
/* -------------------------------------------------------------------------------------------*/
static void
dump_sns_cache(const char *type, const char *account, const char *mac, struct packet_info* p)
{
	int cs = 0;

	if (VF == NULL) 
		return;
	
	/* if time expired or cache file size more than 200K */ 
	if (the_time.tv_sec - the_dumpsns_time.tv_sec > conf.upload_interval 
	    || (cs = ffsize(VF)) > 200*1024 ) {
		virtual_accountfile_open(conf.viraccfile);	
	}

	static char buf[200];
	memset(buf, 0, 200);
	static char typeaccount[64];
	memset(typeaccount, 0, 64);

	struct timeval tv;
	gettimeofday(&tv, NULL);

	if (p != 0) {
		static char wlan_dst[18];
		static char wlan_essid[34];
		memset(wlan_essid, 0, 34);
		memset(wlan_dst, 0, 18);

		memcpy(wlan_dst, mac_smbig_conversion(ether_sprintf(p->wlan_dst)), 17);
		memcpy(wlan_essid, p->wlan_essid, 34);		

		sprintf(typeaccount, "%s:%s", type, account);
		sprintf(buf, "%s\t%s\t%s\t%d\t%d\t%d\t%s\t%s\t%s\t%d\t%s\t%d\t%d\t%c\t%s\t%c\t%c\t%s\r\n", mac_smbig_conversion(mac), phone_brand(mac), 
				essid, tv.tv_sec, sig, id, typeaccount, p->wlan_essid, wlan_dst, p->wlan_channel, des_type(p), X, Y, f, macbuf, f, f, card);

		struct type_content t_content;
		bzero(t_content.buff, sizeof(t_content.buff));
		t_content.type = type_1;
		t_content.length = strlen(buf);
		strcpy(t_content.buff, buf);
		sendto(sockfd, &t_content, sizeof(t_content), 0, (struct sockaddr *)&hostaddr, sizeof(hostaddr));
	}

	if (p != 0) {
		virtual_acc_record(type, account, mac, p);		
	}
}

void*
upload_sns_fun(void *arg)
{
	printlog("upload sns file thread begin...");
	int r, w;
	char cachefile[128];
	
	for (;;) {		
		pthread_mutex_lock(&t_sns_lock);
		
		r = sns_cache_info.rfn;
		w = sns_cache_info.wfn;

		memset(cachefile, 0, 128);
	
		/* has file to upload */ 
		if (w > (r+1))
			r++;
		else if (w < r && (w+sns_cache_info.maxcount) > (r+1)) {
			r++; 			
		}
		if (sns_cache_info.rfn != r) {
			if (r > sns_cache_info.maxcount)		/* circle pointer */
				r = 1;
			if (NULL != conf.viraccfile) {
				sprintf(cachefile, "%s_%d",  conf.viraccfile, r);
				printlog("send sns cache = %s", cachefile);	
			}
			if (strlen(cachefile) && 0 == access(cachefile, R_OK)) {
				sns_cache_info.reading = true;
				sns_cache_info.rfn = r;	
			}
		}

		pthread_mutex_unlock(&t_sns_lock);

		/* now read out */
		if (sns_cache_info.reading == true && fpsize(cachefile) > 0) {
			printlog("sending sns data...");
			
			char *cmd = malloc(512);
			sprintf(cmd, "/opt/scanner/upload.sh sns %s", cachefile);	
			system(cmd);
			free(cmd);
			
			printlog("sending sns data finished");
		}
		else {
			printlog("no sns data to send in this time");
		}

		sns_cache_info.reading = false;	
		
		sleep(2);
	}

	return ((void*)0);
}

/* -------------------------------------------------------------------------------------------*/
/* pcap cache handle */
/* -------------------------------------------------------------------------------------------*/
static bool
write_pcap_cache(char *p, int len)
{
	if (PF == NULL)
		return false;

	if (p == NULL || len == 0)
		return false;

	if (ffsize(PF)<4) { //new file
		// pcap header
		struct pcap_file_header pfhdr;
		pfhdr.magic = le32toh(0xA1B2C3D4);
		pfhdr.version_major = le16toh(0x0002);
		pfhdr.version_minor = le16toh(0x0004);
		pfhdr.thiszone = 0x00000000;
		pfhdr.snaplen = le32toh(0x0000FFFF);
		pfhdr.sigfigs = 0x00000000;
		pfhdr.linktype = le32toh(0x0000007f);	
		fwrite((void *)&pfhdr, sizeof(struct pcap_file_header), 1, PF);
	}
	// packet header			
	struct pcap_pkthdr pkthdr;
	struct timeval ts;
	gettimeofday(&ts, NULL);

	pkthdr.ts.tv_sec = le32toh(ts.tv_sec);
	pkthdr.ts.tv_usec = le32toh(ts.tv_usec);
	pkthdr.caplen = le32toh(len);
	pkthdr.len = le32toh(len);
	fwrite((void *)&pkthdr, sizeof(struct pcap_pkthdr), 1, PF);

	// packet 
	fwrite(p, len, 1, PF);
	fflush(PF);
	
	return true;
}

static void
dump_pcap_cache(char *p, int len)
{
	int cs = 0;

	if (PF == NULL) 
		return;
	
	/* if time expired or cache file size more than 400K */ 
	if (the_time.tv_sec - the_dumppcap_time.tv_sec > conf.upload_interval 
	    || (cs = ffsize(PF)) > 400*1024 ) {
		pcap_file_open();	
	}	
	
	write_pcap_cache(p, len);		
}


void*
upload_pcap_fun(void *arg)
{
	printlog("upload pcap file thread begin...");
	int r, w;
	char cachefile[128];
	
	for (;;) {		
		pthread_mutex_lock(&t_pcap_lock);
		
		r = pcap_cache_info.rfn;
		w = pcap_cache_info.wfn;

		memset(cachefile, 0, 128);
	
		/* has file to upload */ 
		if (w > (r+1))
			r++;
		else if (w < r && (w+pcap_cache_info.maxcount) > (r+1)) {
			r++; 			
		}
		
		if (pcap_cache_info.rfn != r) {
			if (r > pcap_cache_info.maxcount)		/* circle pointer */
				r = 1;
			if (1 == conf.capture) {
				sprintf(cachefile, "%s_%d", const_pcap_filename, r);
				printlog("send pcap cache = %s", cachefile);	
			}
			if (strlen(cachefile) && 0 == access(cachefile, R_OK)) {
				pcap_cache_info.reading = true;
				pcap_cache_info.rfn = r;	
			}
		}

		pthread_mutex_unlock(&t_pcap_lock);

		/* now read out */
		if (pcap_cache_info.reading == true && fpsize(cachefile) > 0) {
			printlog("sending pcap data...");
			
			char *cmd = malloc(512);
			sprintf(cmd, "/opt/scanner/upload.sh pcap %s", cachefile);	
			system(cmd);
			free(cmd);
			
			printlog("sending pcap data finished");

		}
		else {
			printlog("no pcap data to send in this time");
		}

		pcap_cache_info.reading = false;	
		
		sleep(2);
	}

	return ((void*)0);
}


int
udp_cli(void)
{
	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		err(1,"Could not open local socket");
	printf("udp cli sockufd is:%d\n", sockfd);

	bzero(&hostaddr, sizeof(hostaddr));
	hostaddr.sin_family = AF_INET;
	hostaddr.sin_addr.s_addr = inet_addr("192.168.123.100");//htonl(INADDR_ANY);
	hostaddr.sin_port = htons(atoi(conf.port));

	if(connect(sockfd, (struct sockaddr *)&hostaddr, sizeof(hostaddr)) < 0)
	{	
		err(1,"connect failed");
	}
	else
	{
		printf("udp client connect success\n");
	}
	return sockfd;
}

/* r1 and r3 read hmac receive r0 hmac */
void
receive_R0_hmac(void)
{
	FILE *fhmac;
	if ((fhmac = fopen("/opt/scanner/hmac", "r")) == NULL) {
		printf("Open hmac r failed!\n");
	}

	fread(macbuf, 21, 1, fhmac);
	printf("receive macbuf :%s\n", macbuf);
	fclose(fhmac);
	gettimeofday(&the_readmac_time, NULL);
}

static char *
macbuf_smbig_conversion(const char mac[22])
{
	int i = 0;
	static unsigned char wlan_mac[22];

	memset(wlan_mac, 0, 22);
	memcpy(wlan_mac, mac, 21);
	for (i; i < 21; i++) {
		if (wlan_mac[i] >= 'a' && wlan_mac[i] <= 'z')
			wlan_mac[i] -= 32;
	}
	return wlan_mac;
}

static char *
equipment_number_macbuf(void)
{
	static char buf[13], buff[22];
	memset(buf, 0, 13);
	memset(buff, 0, 22);

	FILE *fp = fopen("/opt/scanner/hmac", "r");
	if (fp == NULL) {
		printf("Open brand.txt failed\n");
	}
	if (fgets(buf, sizeof(buf), fp) > 0) {
		fclose(fp);
		sprintf(buff, "111222333%s", buf);
		strncpy(buff, macbuf_smbig_conversion(buff), 21);
	}
	return buff;
}


int
main(int argc, char** argv)
{
	int perr;

	sockfd = udp_cli();

	if (R == 0) {
		/*  If the installation in the R0 perform this lines  */
		strncpy(macbuf, equipment_number_macbuf(), 21);
		printf("main macbuf :%s\n", macbuf);
	}
	if (R == 1 || R == 3) {
		/*  If the installation in the R1 or R3 perform this function  */
		receive_R0_hmac();
	}

	mpkgs = (macpkg *)calloc(MAPPKG_INITIAL_SIZE, sizeof(macpkg));
	mpkghead = mpkgs;
 	printlog("mpkgs value: %d, mpkghead valus: %d \t", mpkgs, mpkghead);	
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

	map = hashmap_create();
	gettimeofday(&the_hashmac_time, NULL);	

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
			printf("(e.g. 'iw %s interface add mon0 type monitor' and 'mty -i mon0')\n", conf.ifname);
			exit(1);
		}

		channel_init();

		if (conf.channel_ini>0) {
			channel_change(channel_find_index_from_chan(conf.channel_ini));
			printf("set channel: %d, ifname: %s\n", conf.channel_idx+1, conf.ifname);
		}

		init_spectrum();
	}

	pthread_mutex_init(&t_sns_lock, NULL);
	pthread_mutex_init(&t_mac_lock, NULL);
	pthread_mutex_init(&t_pcap_lock, NULL);

	if (!conf.quiet && !DO_DEBUG)
		init_display();

	if (conf.dumpfile != NULL)
		dumpfile_open(conf.dumpfile);

	if (conf.bedologfile != NULL)
		bedo_logfile_open(conf.bedologfile);

	if (conf.viraccfile != NULL)
		virtual_accountfile_open(conf.viraccfile);

	if (conf.capture == 1)
		pcap_file_open();
	
	bedo_log(BEDO_LOG_INFO, "conf.arphrd= %s\n", conf.arphrd == ARPHRD_IEEE80211_PRISM?"prism":"radiotap");
	
	/* test */
	/*
	if (conf.printlog) {
		bool db = curl_download("http://nj2.newhua.com/down/rectordecryptor.zip", "/tmp/rd.zip");
		printlog("download sucess = %d", db);
	}*/
	
	if (!conf.serveraddr && conf.port && conf.allow_client)
		net_init_server_socket(conf.port);

#if 0
	if (conf.dumpfile != NULL) {
		perr = pthread_create(&upload_mac_thd, NULL, upload_mac_fun, NULL);
		if (perr != 0) {
			err(1, "upload mac thread create failed:%s", strerror(perr));	
		}
	}
	if (conf.viraccfile != NULL) {	
		perr = pthread_create(&upload_sns_thd, NULL, upload_sns_fun, NULL);
		if (perr != 0) {
			err(1, "upload sns thread create failed:%s", strerror(perr));	
		}
	}
	if (conf.capture == 1) {
		perr = pthread_create(&upload_pcap_thd, NULL, upload_pcap_fun, NULL);
		if (perr != 0) {
			err(1, "upload pcap thread create failed:%s", strerror(perr));	
		}	
	}
#endif
	
	for ( /* ever */ ;;)
	{
		if (R == 1 || R == 3) {
			gettimeofday(&the_sendmac_time, NULL);
			if (the_sendmac_time.tv_sec - the_readmac_time.tv_sec >= 20*60) {
				receive_R0_hmac();
			}
		}

		receive_any();
		gettimeofday(&the_time, NULL);
		timeout_nodes();
		
		/* if there's no new data captured, should change cache file to trigger auto upload thread */ 
		if (DF != NULL && the_time.tv_sec - the_dump_time.tv_sec > conf.upload_interval) {
			dump_mac_cache(NULL);
		}
		if (VF != NULL && the_time.tv_sec - the_dumpsns_time.tv_sec > conf.upload_interval) {
			dump_sns_cache(NULL, NULL, NULL, NULL);
		}
		if (PF != NULL && the_time.tv_sec - the_dumppcap_time.tv_sec > conf.upload_interval) {
			dump_pcap_cache(NULL, 0);
		}

		if (!conf.serveraddr) { /* server */
			if (channel_auto_change()) {
				net_send_channel_config();
				update_spectrum_durations();
				if (!conf.quiet && !DO_DEBUG)
					update_display(NULL);
			}
		}
	}
#if 0
	/* will never */
	if (conf.dumpfile != NULL)
		pthread_join(upload_mac_thd, NULL);
	if (conf.viraccfile != NULL)
		pthread_join(upload_sns_thd, NULL);
	if (conf.capture == 1)
		pthread_join(upload_pcap_thd, NULL);
#endif

	hashmap_destroy(map, free_macpkg, 0);
	close(sockfd);
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
	char cachefile[256];
	int w, r;

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
	
	pthread_mutex_lock(&t_mac_lock);

	w = mac_cache_info.wfn;
	r = mac_cache_info.rfn;
	/* circle file pointer, maybe cover those not be uploaded */
	while(1) {
		w++;
		if (w > mac_cache_info.maxcount) {
			w = 1;
		}
		if (w != r) {
			mac_cache_info.wfn = w;
			break;
		}
	}
	sprintf(cachefile, "%s_%d", name, w);	
	
	pthread_mutex_unlock(&t_mac_lock);
	
	DF = fopen(cachefile, "w");
	
	if (DF == NULL)
		err(1, "Couldn't open dump file");

	gettimeofday(&the_dump_time, NULL);
	printlog("- Writing to outfile %s", cachefile);
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
	char cachefile[256];
	int w, r;
	
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

	pthread_mutex_lock(&t_sns_lock);

	w = sns_cache_info.wfn;
	r = sns_cache_info.rfn;
	/* circle file pointer, maybe cover those not be uploaded */
	while(1) {
		w++;
		if (w > sns_cache_info.maxcount) {
			w = 1;
		}
		if (w != r) {
			sns_cache_info.wfn = w;
			break;
		}
	}
	sprintf(cachefile, "%s_%d", name, w);	
	pthread_mutex_unlock(&t_sns_lock);
	
	VF = fopen(cachefile, "w");
	
	if (VF == NULL)
		err(1, "Couldn't open virtual sns file");

	gettimeofday(&the_dumpsns_time, NULL);
	printlog("- virtual account file %s", cachefile);
}

void 
pcap_file_open()
{
	char pcapfile[256]; 	
	int w, r;
	
	if (PF != NULL) {
		fclose(PF);
		PF = NULL;
	}
	memset(pcapfile, 0, 256);
	pthread_mutex_lock(&t_pcap_lock);

	w = pcap_cache_info.wfn;
	r = pcap_cache_info.rfn;
	/* circle file pointer, maybe cover those not be uploaded */
	while(1) {
		w++;
		if (w > pcap_cache_info.maxcount) {
			w = 1;
		}
		if (w != r) {
			pcap_cache_info.wfn = w;
			break;
		}
	}
	sprintf(pcapfile, "%s_%d", const_pcap_filename, w);	

	pthread_mutex_unlock(&t_pcap_lock);
	
	PF = fopen(pcapfile, "w");
	
	if (PF == NULL)
		err(1, "Couldn't open packet capture file");

	gettimeofday(&the_dumppcap_time, NULL);
	printlog("- packet capture file %s", pcapfile);
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
