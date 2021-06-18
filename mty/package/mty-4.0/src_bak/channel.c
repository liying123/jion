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

#include <stdlib.h>

#include "main.h"
#include "util.h"
#include "wext.h"
#include "channel.h"


#if defined(__APPLE__)

int
channel_change(__attribute__((unused)) int idx)
{
	return 0;
}

int
channel_auto_change(void)
{
	return 0;
}

int
channel_find_index_from_chan(__attribute__((unused)) int c)
{
	return -1;
}

void
get_current_channel(__attribute__((unused)) int mon)
{
}


#else


static struct timeval last_channelchange;
extern int mon; /* monitoring socket */
static struct chan_freq channels[MAX_CHANNELS];


int
channel_change(int idx)
{
	if (wext_set_freq(mon, conf.ifname, channels[idx].freq) == 0) {
		printlog("ERROR: could not set channel %d", channels[idx].chan);
		return 0;
	}
	conf.channel_idx = idx;
	return 1;
}


int
channel_auto_change(void)
{
	int new_chan;
	int ret = 1;
	int start_chan;

	if (the_time.tv_sec == last_channelchange.tv_sec &&
	    (the_time.tv_usec - last_channelchange.tv_usec) < conf.channel_time)
		return 0; /* too early */

	if (conf.do_change_channel) {
		start_chan = new_chan = conf.channel_idx;
		do {
			new_chan = new_chan + 1;
			if (new_chan >= conf.num_channels ||
			    new_chan >= MAX_CHANNELS ||
			    (conf.channel_max && new_chan >= conf.channel_max))
				new_chan = 0;

			ret = channel_change(new_chan);

		/* try setting different channels in case we get errors only
		 * on some channels (e.g. ipw2200 reports channel 14 but cannot
		 * be set to use it). stop if we tried all channels */
		} while (ret != 1 && new_chan != start_chan);
	}

	last_channelchange = the_time;
	return ret;
}


int
channel_find_index_from_chan(int c)
{
	int i = -1;
	for (i = 0; i < conf.num_channels && i < MAX_CHANNELS; i++)
		if (channels[i].chan == c)
			return i;
	return -1;
}


int
channel_find_index_from_freq(int f)
{
	int i = -1;
	for (i = 0; i < conf.num_channels && i < MAX_CHANNELS; i++)
		if (channels[i].freq == f)
			return i;
	return -1;
}


int
channel_get_chan_from_idx(int i) {
	if (i >= 0 && i < conf.num_channels && i < MAX_CHANNELS)
		return channels[i].chan;
	else
		return -1;
}


int
channel_get_current_chan() {
	return channel_get_chan_from_idx(conf.channel_idx);
}

int 
channel_get_config_chan() {
	FILE *fp;
	int chan = -1;
	char buf[256];
	char *flag = "option channel";

	fp = fopen("/etc/config/wireless", "r");
	if (NULL == fp)
		return -1;
	
	while(fgets(buf, sizeof(buf), fp)) {
		char *p = strstr(buf, flag);
		if (p) {
			p = p + strlen(flag);
			chan = atoi(p);
			break;
		}
	}
	
	fclose(fp);

	return chan;
}

static int
get_current_wext_channel_idx(int mon)
{
	int freq, ch;

	/* get current channel &  map to our channel array */
	freq = wext_get_freq(mon, conf.ifname);
	if (freq == 0) {
		printlog("can't get %s freq", conf.ifname);
		return -1;
	}

	ch = channel_find_index_from_freq(freq);

	printlog("current ch=%d, freq=%d", ch, freq);

	DEBUG("***%d\n", ch);
	return ch;
}


void
channel_init(void) {
	/* get available channels */
	conf.num_channels = wext_get_channels(mon, conf.ifname, channels);
	conf.channel_idx = get_current_wext_channel_idx(mon);
}


struct chan_freq*
channel_get_struct(int i) {
	if (i < conf.num_channels && i < MAX_CHANNELS)
		return &channels[i];
	return NULL;
}


void
channel_set(int i, int chan, int freq) {
	if (i < conf.num_channels && i < MAX_CHANNELS) {
		channels[i].chan = chan;
		channels[i].freq = freq;
	}
}

#endif
