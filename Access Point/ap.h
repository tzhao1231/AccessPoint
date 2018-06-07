//
//  ap.h
//  Access Point
//
//  Created by apple on 2018/5/13.
//  Copyright © 2018年 battlefire. All rights reserved.
//

#ifndef ap_h
#define ap_h
#include <stdio.h>

typedef struct RssiList {
    int exp_date;// Expiration date int rl rssi value ;
    int rl_rssi_value;
    struct RssiList * rl_next ;
} RssiList ;

typedef struct DeviceList {
    char dl_mac_address [ 6 ] ;
    RssiList * dl_rssi_list ;
    struct DeviceList * dl_next ;
} DeviceList ;

void add_device ( DeviceList **l , char mac_addr[6] );
void clear_device_list ( DeviceList **l );
void add_rssi_sample ( DeviceList *l , int rssi_value, int date);
void clear_rssi_list ( DeviceList *l );
void delete_outdated ( DeviceList *l , int current_time );
float getRssi(DeviceList *l);
double getTime(struct timeval *current_time, struct timeval *rssi_time);
void printDevice(DeviceList *l);
DeviceList* find_Device(DeviceList*l, char *mac_addr);
//UDP listening/////////////////////
#define MYPORT 7777
#define CONNECTPORT 9999
#define MAXBUFLEN 5000
static void *udp_listening(void *ptr);
DeviceList * deviceList;
///////////////////////////////////////////////////////////
//rssi listening///////////////////////////////////////////
//these 3 struct below are used to obtain the rssi and mac address from device
struct ieee80211_header {
    u_short frame_control;
    u_short frame_duration;
    u_char recipient[6];
    u_char source_addr[6];
    u_char address3[6];
    u_short sequence_control;
    u_char address4[6];
};
struct prism_header *ph;
struct ieee80211_header * eh;
struct pcap_pkthdr header;
///////////////////////////////////////////////////////////////
static void *rssi_listening(void *ptr);
#endif /* ap_h */
