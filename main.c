#include <pthread.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>

#include "capture/common.h"
#include "capture/osdep.h"
#include "utils/utils.h"
#include "utils/wifi_scan.h"

#include "airkiss.h"

#define MAX_CHANNELS (14)
#define DEBUG (0)
#define RANDOM_ACK_PORT (10000)
#define ONLINE_NOTIFY_PORT (12476)

#define DEVICE_TYPE   "gh_a88096b14315"
#define DEVICE_ID     "gh_a88096b14315_e5604bc883bf7eb1"

static airkiss_context_t *akcontex = NULL;
const airkiss_config_t akconf = {
(airkiss_memset_fn)&memset,
(airkiss_memcpy_fn)&memcpy,
(airkiss_memcmp_fn)&memcmp,
(airkiss_printf_fn)&printf };

airkiss_result_t ak_result;
struct itimerval my_timer;
int startTimer(struct itimerval *timer, int ms);
int udp_10000_broadcast_ap_connected(unsigned char random, int port,
                                      struct sockaddr_in* broadcast_addr);

int udp_12476_broadcast_dev_online_req_ack(void* port_num);
int udp_12476_broadcast_dev_online_5s_timer(void* port_fd);

char   *wifi_if = NULL;
struct wif *wi  = NULL;

int g_channels[MAX_CHANNELS] = {0};
int g_channel_index = 0;
int g_channel_nums = 0;
int g_dev_port_num = ONLINE_NOTIFY_PORT;
int g_dev_port_fd  = -1;
struct sockaddr_in g_host_addr;
struct sockaddr_in g_netmask_addr;
struct sockaddr_in g_broadcast_addr;

// mutex for airkiss main thread and switch channel timer
pthread_mutex_t lock;
// mutex lock for req&ack thread and 5s timer thread
pthread_mutex_t t_lock;
// thread for wechat req and dev ack
pthread_t tq_id;
struct sched_param tq_sche_param;
pthread_attr_t tq_attr;
int tq_policy=0;
// thread for 5 timer notify
pthread_t tn_id;
struct sched_param tn_sche_param;
pthread_attr_t tn_attr;
int tn_policy=0;


int checkIFip(char* if_name, struct sockaddr_in* host_addr,
	      struct sockaddr_in* netmask_addr, struct sockaddr_in* broadcast_addr)
{
  struct ifaddrs *ifaddr, *ifa;
  int s, ret = -1;
  char host[NI_MAXHOST] = {0};
  char netmask[NI_MAXHOST] = {0};
  char broadcast[NI_MAXHOST] ={0};

  if (getifaddrs(&ifaddr) == -1) {
      LOG_TRACE("getifaddrs failed!");
      return -1;
  }

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
      if (ifa->ifa_addr == NULL) {
	LOG_TRACE("ifa_addr is NULL");
	continue;
      }

      s = getnameinfo(ifa->ifa_broadaddr, sizeof(struct sockaddr_in), broadcast, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
      s = getnameinfo(ifa->ifa_netmask, sizeof(struct sockaddr_in), netmask, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
      s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

      if((strcmp(ifa->ifa_name, if_name)==0) && (ifa->ifa_addr->sa_family==AF_INET)) {
	  if (s != 0) {
	      LOG_TRACE("getnameinfo() failed: %s", gai_strerror(s));
	      break;
	  }
	  memcpy(host_addr, ifa->ifa_addr, sizeof(struct sockaddr_in));
	  memcpy(netmask_addr, ifa->ifa_netmask, sizeof(struct sockaddr_in));
	  memcpy(broadcast_addr, ifa->ifa_broadaddr, sizeof(struct sockaddr_in));
	  LOG_TRACE("\tInterface   : <%s>", ifa->ifa_name );
	  LOG_TRACE("\t  Address   : <%s>", host);
	  LOG_TRACE("\t  Netmask   : <%s>", netmask);
	  LOG_TRACE("\t  Broadcast : <%s>", broadcast);
          ret = 0;
	  break;
      }
  }

  freeifaddrs(ifaddr);
  return ret;
}

//crc8
unsigned char calcrc_1byte(unsigned char abyte)
{
    unsigned char i,crc_1byte;
    crc_1byte=0;
    for(i = 0; i < 8; i++) {
        if(((crc_1byte^abyte)&0x01)) {
            crc_1byte^=0x18;
            crc_1byte>>=1;
            crc_1byte|=0x80;
        }
        else {
            crc_1byte>>=1;
        }
        abyte>>=1;
    }
    return crc_1byte;
}


unsigned char calcrc_bytes(unsigned char *p,unsigned int num_of_bytes)
{
    unsigned char crc=0;
    while(num_of_bytes--) {
        crc=calcrc_1byte(crc^*p++);
    }
    return crc;
}

void switch_channel_callback(void)
{
    pthread_mutex_lock(&lock);
    g_channel_index++;
    if(g_channel_index > g_channel_nums - 1)
    {
        g_channel_index = 0;
        LOG_TRACE("scan all channels");
    }
	int ret = wi->wi_set_channel(wi, g_channels[g_channel_index]);
	if (ret) {
		LOG_TRACE("cannot set channel to %d", g_channels[g_channel_index]);
	}

    airkiss_change_channel(akcontex);
    pthread_mutex_unlock(&lock);
}

int fork_device_online_req_ack_thread()
{
    if(pthread_attr_init(&tq_attr) == 0) {
        pthread_attr_getschedpolicy(&tq_attr, &tq_policy);
        tq_sche_param.sched_priority = sched_get_priority_min(tq_policy);
        pthread_attr_setschedparam(&tq_attr, &tq_sche_param);
        if(pthread_create(&tq_id, &tq_attr, (void * (*)(void *))&udp_12476_broadcast_dev_online_req_ack,
                          (void*)&g_dev_port_num) == 0) {
            LOG_TRACE("Create device online req&ack thread:%d", (int)tq_id);
            pthread_detach(tq_id);
        } else {
            LOG_TRACE("Create device online req&ack thread failed!");
            return -1;
        }
    }
    return 0;
}

int fork_device_online_5s_notify_thread()
{
    if(pthread_attr_init(&tn_attr) == 0) {
        pthread_attr_getschedpolicy(&tn_attr, &tn_policy);
        tn_sche_param.sched_priority = sched_get_priority_min(tn_policy);
        pthread_attr_setschedparam(&tn_attr, &tn_sche_param);
        if(pthread_create(&tn_id, &tn_attr, (void * (*)(void *))&udp_12476_broadcast_dev_online_5s_timer,
                          (void*)&g_dev_port_fd) == 0) {
            LOG_TRACE("Create device online 5s notify thread:%d", (int)tn_id);
            pthread_join(tn_id, NULL);
        } else {
            LOG_TRACE("Create device online 5s notify thread failed!");
            return -1;
        }
    }
    return 0;
}

int process_airkiss(const unsigned char *packet, int size)
{
    char cmd_buf[256] = {0};
    pthread_mutex_lock(&lock);
    int ret;

    ret = airkiss_recv(akcontex, (void *)packet, size);
    if(ret == AIRKISS_STATUS_CONTINUE)
    {
        // LOG_TRACE("Airkiss continue");
    }
    else if(ret == AIRKISS_STATUS_CHANNEL_LOCKED)
    {
        startTimer(&my_timer, 0);
        LOG_TRACE("Lock channel in %d", g_channels[g_channel_index]);
    }
    else if(ret == AIRKISS_STATUS_COMPLETE)
    {
        LOG_TRACE("Airkiss completed.");
        airkiss_get_result(akcontex, &ak_result);
        LOG_TRACE("Result:\nssid_crc:[%x]\nkey_len:[%d]\nkey:[%s]\nrandom:[%d]", 
            ak_result.reserved,
            ak_result.pwd_length,
            ak_result.pwd,
            ak_result.random);

        // scan and connect to wifi
        system("rm -rf /etc/wpa_supplicant/wpa_supplicant.conf");
        sprintf(cmd_buf, "wpa_passphrase %s %s > /etc/wpa_supplicant/wpa_supplicant.conf", ak_result.ssid, ak_result.pwd);
        system(cmd_buf);
        memset(cmd_buf, 0, 256);
        sprintf(cmd_buf, "wpa_supplicant -i %s -c /etc/wpa_supplicant/wpa_supplicant.conf -B", wifi_if);
        system(cmd_buf);
        do{
            sleep(1);
        } while(checkIFip(wifi_if, &g_host_addr, &g_netmask_addr, &g_broadcast_addr) == -1);
	udp_10000_broadcast_ap_connected(ak_result.random, RANDOM_ACK_PORT, &g_broadcast_addr);
    }
    pthread_mutex_unlock(&lock);

    return ret;
}

void add_channel(int chan) {
    int i;
    for(i=0; i<g_channel_nums; i++) {
        if(g_channels[i]==chan)
            break;
    }
    if(i==g_channel_nums) {
        g_channel_nums += 1;
        g_channels[i] = chan;
    }
}

void init_channels()
{
    int i;
    for(i=1; i<MAX_CHANNELS; i++)
    {
        add_channel(i);
    }
}


int startTimer(struct itimerval *timer, int ms)
{
    time_t secs, usecs;
    secs = ms/1000;
    usecs = ms%1000 * 1000;

    timer->it_interval.tv_sec = secs;
    timer->it_interval.tv_usec = usecs;
    timer->it_value.tv_sec = secs;
    timer->it_value.tv_usec = usecs;

    setitimer(ITIMER_REAL, timer, NULL);
    return 0;
}

int udp_10000_broadcast_ap_connected(unsigned char random, int port, struct sockaddr_in* broadcast_addr)
{
    int fd, status, sinlen;
    int enabled = 1;
    struct sockaddr_in addr;

    sinlen = sizeof(struct sockaddr_in);
    memset(&addr, 0, sinlen);
    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(0);
    addr.sin_family = PF_INET;

    status = bind(fd, (struct sockaddr *)&addr, sinlen);
    // LOG_TRACE("Bind Status = %d", status);

    status = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &enabled, sizeof(int));
    // LOG_TRACE("Setsockopt Status = %d", status);

    //addr.sin_addr.s_addr=htonl(INADDR_BROADCAST); /* send message to 255.255.255*/
    memcpy(&addr, broadcast_addr, sizeof(struct sockaddr_in));
    //addr.sin_addr.s_addr = inet_addr("255.255.255.255");  
    addr.sin_port = htons(port); /* port number */
    //addr.sin_family = PF_INET;

    int i;
    useconds_t usecs = 1000*20;
    for(i=0; i<20; i++)
    {
        status = sendto(fd, &random, 1, 0, (struct sockaddr*)&addr, sizeof(struct sockaddr));
        usleep(usecs);
    }
    LOG_TRACE("send 20 received random data(%d) to WeChat, result = %d", random, status);

    shutdown(fd, 2);
    close(fd);
    return 0;
}

int udp_12476_broadcast_dev_online_req_ack(void* pt_num)
{
    int fd, status;
    size_t addr_len;
    int port = *((int*)pt_num);
    struct sockaddr_in addr_in, addr_out;
    uint8_t  lan_buf_in[200] = {0};
    uint16_t lan_buf_in_len = 0;
    uint8_t  lan_buf[200] = {0};
    uint16_t lan_buf_len = 0;
    airkiss_lan_ret_t packret;
    char dst_ip[NI_MAXHOST] = {0};
    int is_exit = 0;
    int i = 0;

    pthread_mutex_lock(&t_lock);
    addr_len = sizeof(struct sockaddr_in);
    memset(&addr_in,  0, addr_len);
    memset(&addr_out, 0, addr_len);
    g_dev_port_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    fd = g_dev_port_fd;
    addr_in.sin_addr.s_addr = htonl(INADDR_ANY);
    addr_in.sin_port = htons(port);
    addr_in.sin_family = PF_INET;

    status = bind(fd, (struct sockaddr *)&addr_in, addr_len);
    LOG_TRACE("req&ack thread bind Status = %d, port = %d, fd = %d", status, port, fd);
    //pthread_mutex_unlock(&t_lock);

    while(1) {
        //pthread_mutex_lock(&t_lock);
        is_exit = 0;
        memset(lan_buf_in, 0, 200);
        lan_buf_in_len = recvfrom(fd, lan_buf_in, 200, 0, (struct sockaddr *)&addr_out, &addr_len);
        getnameinfo(&addr_out, sizeof(struct sockaddr_in), dst_ip, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        addr_out.sin_family = PF_INET;
        if(lan_buf_in_len != -1) {
            packret = airkiss_lan_recv(lan_buf_in, lan_buf_in_len, &akconf);
            switch (packret){
                case AIRKISS_LAN_SSDP_REQ:
                    memset(lan_buf, 0, 200);
                    lan_buf_len = sizeof(lan_buf);
                    packret = airkiss_lan_pack(AIRKISS_LAN_SSDP_RESP_CMD, DEVICE_TYPE, DEVICE_ID, 0, 0,
                                               lan_buf, &lan_buf_len, &akconf);
                    if (packret != AIRKISS_LAN_PAKE_READY) {
                        LOG_TRACE("req&ack thread airkiss pack lan packet error, ret = %d", packret);
                    }
                    else {
                        for(i=0; i<10; i++) {
                            status = sendto(fd, lan_buf, lan_buf_len, 0, (struct sockaddr*)&addr_out, sizeof(struct sockaddr));
                            LOG_TRACE("Reply AIRKISS_LAN_SSDP_REQ respone to WeChat(%s:%d), len = %d", dst_ip, ntohs(addr_out.sin_port), status);
                        }
			is_exit = 1;
/*
                        for(i=0; i<20; i++) {
                           LOG_TRACE("%d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d",
                           lan_buf[i*10+0],  lan_buf[i*10+1],  lan_buf[i*10+2],  lan_buf[i*10+3],  lan_buf[i*10+4],
                           lan_buf[i*10+5],  lan_buf[i*10+6],  lan_buf[i*10+7],  lan_buf[i*10+8],  lan_buf[i*10+9],
                           lan_buf[i*10+10], lan_buf[i*10+11], lan_buf[i*10+12], lan_buf[i*10+13], lan_buf[i*10+14],
                           lan_buf[i*10+15], lan_buf[i*10+16], lan_buf[i*10+17], lan_buf[i*10+18], lan_buf[i*10+19]);
                        }
*/
                    }
                    break;
                default:
                    break;
            }
        }

	if(is_exit == 1) {
	    pthread_mutex_unlock(&t_lock);
	    break;
        }
    }

    //shutdown(fd, 2);
    //close(fd);
    return 0;
}

int udp_12476_broadcast_dev_online_5s_timer(void* pt_fd)
{
    int status;
    int enabled = 1;
    int fd = *((int*)pt_fd);
    struct sockaddr_in addr;
    uint8_t  lan_buf[200] = {0};
    uint16_t lan_buf_len;
    airkiss_lan_ret_t packret;
    char dst_ip[NI_MAXHOST] = {0};
//    int i = 0;

    if(fd == -1) {
        LOG_TRACE("device local socket fd is -1!");
        return -1;
    }

    //memcpy(&addr, &g_broadcast_addr, sizeof(struct sockaddr_in));
    //addr.sin_addr.s_addr=htonl(INADDR_BROADCAST); /* send message to 255.255.255.255*/
    //addr.sin_addr.s_addr=htonl(-1);
    addr.sin_addr.s_addr = inet_addr("255.255.255.255");
    addr.sin_port = htons(ONLINE_NOTIFY_PORT); /* port number */
    addr.sin_family = PF_INET;

    while(1) {
        pthread_mutex_lock(&t_lock);
        memset(lan_buf, 0 , 200);
	lan_buf_len = sizeof(lan_buf);
	packret = airkiss_lan_pack(AIRKISS_LAN_SSDP_NOTIFY_CMD, DEVICE_TYPE, DEVICE_ID, 0, 0, lan_buf, &lan_buf_len, &akconf);
	if (packret != AIRKISS_LAN_PAKE_READY) {
	    LOG_TRACE("5s timer thread airkiss Pack lan packet error, ret = %d!", packret);
	}
	else {
            enabled =1;
	    status = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &enabled, sizeof(int));
	    //	    LOG_TRACE("5s timer thread Setsockopt fd = %d, enabled = %d, Status = %d", fd, enabled, status);
            getnameinfo(&addr, sizeof(struct sockaddr_in), dst_ip, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
	    status = sendto(fd, lan_buf, lan_buf_len, 0, (struct sockaddr*)&addr, sizeof(struct sockaddr));
            LOG_TRACE("Send AIRKISS_LAN_SSDP_NOTIFY_CMD command to WeChat(%s:%d), len = %d", dst_ip, ntohs(addr.sin_port), status);
/*
            for(i=0; i<20; i++) {
                LOG_TRACE("%d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d",
                lan_buf[i*10+0],  lan_buf[i*10+1],  lan_buf[i*10+2],  lan_buf[i*10+3],  lan_buf[i*10+4],
                lan_buf[i*10+5],  lan_buf[i*10+6],  lan_buf[i*10+7],  lan_buf[i*10+8],  lan_buf[i*10+9],
                lan_buf[i*10+10], lan_buf[i*10+11], lan_buf[i*10+12], lan_buf[i*10+13], lan_buf[i*10+14],
                lan_buf[i*10+15], lan_buf[i*10+16], lan_buf[i*10+17], lan_buf[i*10+18], lan_buf[i*10+19]);
            }
*/
	    enabled = 0;
            status = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &enabled, sizeof(int));
	    //	    LOG_TRACE("5s timer thread Setsockopt fd = %d, enabled = %d, Status = %d", fd, enabled, status);
	}
        pthread_mutex_unlock(&t_lock);
        sleep(5);
    }

    shutdown(fd, 2);
    close(fd);
    return 0;
}

int main(int argc, char *argv[])
{
    if(argc!=2)
    {
        LOG_ERROR("Usage: %s <device-name>", argv[0]);
        return 1;
    }

    system("killall wpa_supplicant");
    wifi_if = argv[1];

    wireless_scan_head head;
    wireless_scan *presult = NULL;
    LOG_TRACE("Scanning accesss point...");
    if(wifi_scan(wifi_if, &head) == 0)
    {
        LOG_TRACE("Scan success.");
        presult = head.result;
        while(presult != NULL) {
            char essid[MAX_ESSID_SIZE];
            char bssid[MAX_BSSID_SIZE];
            unsigned int freq;
            int channel,power;
            unsigned char essid_crc;

            get_essid(presult, essid, MAX_ESSID_SIZE);
            get_bssid(presult, bssid, MAX_BSSID_SIZE);
            freq = get_freq_mhz(presult);
            power = get_strength_dbm(presult);

            channel = getChannelFromFrequency(freq);
            essid_crc = calcrc_bytes((unsigned char*)essid, strlen(essid));

            LOG_TRACE("bssid:[%s], channel:[%2d], pow:[%d dBm], essid_crc:[%02x], essid:[%s]",
                    bssid, channel, power, essid_crc, essid);
            add_channel(channel);
            presult = presult->next;
        }
    }
    else
    {
        LOG_ERROR("ERROR to scan AP, init with all %d channels", MAX_CHANNELS);
        init_channels();
    }

    /* Open the interface and set mode monitor */
    wi = wi_open(wifi_if);
    if (!wi) {
	LOG_ERROR("cannot init interface %s", wifi_if);
	return 1;
    }

    /* airkiss setup */
    int result;
    akcontex = (airkiss_context_t *)malloc(sizeof(airkiss_context_t));
    result = airkiss_init(akcontex, &akconf);
    if(result != 0)
    {
        LOG_ERROR("Airkiss init failed!!");
        return 1;
    }
    LOG_TRACE("Airkiss version: %s", airkiss_version());
    if(pthread_mutex_init(&lock, NULL) != 0)
    {
        LOG_ERROR("mutex init failed");
        return 1;
    }

    /* Setup channel switch timer */
    startTimer(&my_timer, 400);
    signal(SIGALRM,(__sighandler_t)&switch_channel_callback);

    int read_size;
    unsigned char buf[RECV_BUFSIZE] = {0};
    for(;;)
    {
	read_size = wi->wi_read(wi, buf, RECV_BUFSIZE, NULL);
	if (read_size < 0) {
            LOG_ERROR("recv failed, ret %d", read_size);
            break;
	}
        if(AIRKISS_STATUS_COMPLETE==process_airkiss(buf, read_size)) {
            // break;
	    if(pthread_mutex_init(&t_lock, NULL) != 0) {
	        LOG_ERROR("init t_lock failed!");
	    }
	    else {
                fork_device_online_req_ack_thread();
                fork_device_online_5s_notify_thread();
	    }
	}
     }

    free(akcontex);
    pthread_mutex_destroy(&lock);
    return 0;
}
