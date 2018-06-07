//
//  ap.c
//  Access Point
//
//  Created by apple on 2018/5/13.
//  Copyright © 2018年 battlefire. All rights reserved.
//

#include "ap.h"
// general header files for socket programming
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
//#include <malloc.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <fcntl.h>
#include <fcntl.h>
#include <net/if.h>
////////////////////////////////////////////////
#include <sys/time.h>
#include <utime.h>
#include <time.h>

#include"prism.h"
#include<pthread.h>
#include<pcap.h>//for lipcap
///////////////////////////////////////////////////////////
void add_device ( DeviceList **l , char mac_addr[6] ){
    DeviceList *newDevice=(DeviceList*)malloc(sizeof(DeviceList));
    strcpy(newDevice->dl_mac_address,mac_addr);
    newDevice->dl_rssi_list=NULL;
    newDevice->dl_next=NULL;
    if (l==NULL) {
        l=&newDevice;
    }
    else{
        DeviceList *temp=*l;
        while(temp->dl_next!=NULL){
            temp=temp->dl_next;
        }
        temp->dl_next=newDevice;
    }
}
//////////////////////////////////////////////////////////
void clear_device_list ( DeviceList **l ){
    if((*l)==NULL)
        return;
    else{
        clear_device_list(&(*l)->dl_next);
        free(*l);
    }
}
///////////////////////////////////////////////////////////
void add_rssi_sample ( DeviceList *l , int rssi_value, int date ){
    RssiList *rssilist=(RssiList*)malloc(sizeof(RssiList));
    rssilist->rl_rssi_value=rssi_value;
    rssilist->exp_date=date;
    rssilist->rl_next=NULL;
    if(l->dl_rssi_list==NULL){
        l->dl_rssi_list=rssilist;
        l->dl_rssi_list->rl_next=NULL;
        return;
    }
    else{
        RssiList * temp=l->dl_rssi_list;
        while(temp->rl_next!=NULL){
            temp=temp->rl_next;
        }
        temp->rl_next=rssilist;
        temp->rl_next->rl_next=NULL;
    }
}
///////////////////////////////////////////////////////////
void clear_rssi_list ( DeviceList *l ){
    RssiList *rssilist=l->dl_rssi_list;
    RssiList *temp;
    while(rssilist!=NULL){
        temp=rssilist->rl_next;
        free(rssilist);
        rssilist=temp;
    }
    l->dl_rssi_list=NULL;
}
///////////////////////////////////////////////////////////
void delete_outdated ( DeviceList *l , int current_time ){
    if(l->dl_rssi_list==NULL){
        return;
    }
    else{
        RssiList *rssilist=l->dl_rssi_list;
        RssiList *previousRssi=NULL;
        while(rssilist!=NULL){
            if(rssilist->exp_date<=current_time){
                if(previousRssi==NULL){
                    l->dl_rssi_list=rssilist->rl_next;
                    free(rssilist);
                    rssilist=l->dl_rssi_list;
                }
                else{
                    previousRssi->rl_next=rssilist->rl_next;
                    free(rssilist);
                    rssilist=previousRssi->rl_next;
                }
            }
            
            else{
                previousRssi->rl_next=rssilist;
                rssilist=rssilist->rl_next;
            }
        }
    }
}
///////////////////////////////////////////////////////////
float getRssi(DeviceList *l){
    float rssi_moy=0;
    int num=0;
    RssiList *rssi = l->dl_rssi_list;
    while(rssi){
        //convert in watts, w = 10^(db/10)
        rssi_moy+=pow(10,(rssi->rl_rssi_value/10.0f));
        num++;
        rssi = rssi->rl_next;
    }
    rssi_moy=rssi_moy/num;
    return 10* log10(rssi_moy);
}
///////////////////////////////////////////////////////////
double getTime(struct timeval *current_time, struct timeval *rssi_time) {
    struct timeval *result = NULL;
    
    /* Perform the carry for the later subtraction by updating y. */
    if (current_time->tv_usec < rssi_time->tv_usec) {
        int nsec = (rssi_time->tv_usec - current_time->tv_usec) / 1000000 + 1;
        rssi_time->tv_usec -= 1000000 * nsec;
        rssi_time->tv_sec += nsec;
    }
    if (current_time->tv_usec - rssi_time->tv_usec > 1000000) {
        int nsec = (rssi_time->tv_usec - rssi_time->tv_usec) / 1000000;
        rssi_time->tv_usec += 1000000 * nsec;
        rssi_time->tv_sec -= nsec;
    }
    
    /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
    result->tv_sec = current_time->tv_sec - rssi_time->tv_sec;
    result->tv_usec = current_time->tv_usec - rssi_time->tv_usec;
    
    /* Return 1 if result is negative. */
    return result->tv_sec;
}
///////////////////////////////////////////////////////////
void printDevice(DeviceList *l){
    while(l){
        printf("Mac sddress: %02x:%02x:%02x:%02x:%02x:%02x\n",l->dl_mac_address[0],l->dl_mac_address[1],
               l->dl_mac_address[2],l->dl_mac_address[3],l->dl_mac_address[4],l->dl_mac_address[5]);
        RssiList *rssi = l->dl_rssi_list;
        while(rssi){
            printf("RSSI=%d",rssi->rl_rssi_value);
            printf("Date=%d\n",rssi->exp_date);
            rssi=rssi->rl_next;
        }
    }
}
///////////////////////////////////////////////////////////
DeviceList* find_Device(DeviceList*l, char* mac_addr){
    DeviceList *devicelist = l;
    while(devicelist !=NULL){
        if(strcmp(devicelist->dl_mac_address,mac_addr)){
            return devicelist;
        }
        devicelist=devicelist->dl_next;
    }
    return NULL;
}
///////////////////////////////////////////////////////////
static void *udp_listening(void *ptr){
   // char *message;
#define MYPORT 7777
#define YOURPORT 9999
    int sockfd,sockbw;
    struct sockaddr_in my_addr;
    struct sockaddr_in your_addr;
    int addr_len,numbytes;
    char buf[MAXBUFLEN];
    
    sockfd= socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd<0){
        perror("Could not open socket\n");
        exit(1);
    }
    my_addr.sin_family=AF_INET;
    my_addr.sin_port= htons(MYPORT);
    if(bind(sockfd, (struct sockaddr*)&my_addr, sizeof(struct sockaddr))==-1){
        perror("Error when binding socket\n");
        exit(1);
    }
    ///////////////get the ap_mc_addr///////////////////
    //struct ifreq s;
    //strcpy(s.ifr_name, "eth0");
    //ioctl(sockfd, SIOCGIFHWADDR, &s);
    // Mac Addr:   s.ifr_addr.sa_data[i]
    //printf("Thread 'Communicaton' launched\n");
    addr_len=sizeof(struct sockaddr);
    while(1){
        int n=0;
        if(numbytes=recvfrom(sockfd, buf, MAXBUFLEN, 0, (struct sockaddr *)&your_addr, &addr_len)>0){
            buf[n] = 0;
            printf("Received: %s\n", buf);
            char* cmd = strtok(buf, ";");
            if(strcmp(cmd, "OFFLINE") == 0)
            {
                char* positionX = strtok(NULL, ";");
                char* positionY = strtok(NULL, ";");
                //char* mapID = strtok(NULL, ";");
                char* addr = strtok(NULL, ";");
                printf("Received: %s, %s, %s\n", positionX, positionY,addr);
               // printf("Received: %s, %s, %s, %s\n", positionX, positionY, mapID, addr);
                if(!positionX || !positionY || !addr)
              //  if(!positionX || !positionY || !mapID || !addr)
                    continue;
                if(    strcmp(positionX, "null") == 0|| strcmp(positionY, "null") == 0|| strcmp(addr, "null") == 0)
                    // || strcmp(mapID, "null") == 0
                continue;
                char mac_addr[6];
                sscanf(addr, "%x:%x:%x:%x:%x:%x",     (int*) &mac_addr[0],
                       (int*) &mac_addr[1],
                       (int*) &mac_addr[2],
                       (int*) &mac_addr[3],
                       (int*) &mac_addr[4],
                       (int*) &mac_addr[5]);
                //pthread_mutex_lock(&mDeviceList);
                DeviceList* find = find_Device(deviceList, mac_addr);
                if(find)
                {
                    printf("> Device Found: %02x:%02x:%02x:%02x:%02x:%02x\n",
                           (unsigned char) find->dl_mac_address[0],
                           (unsigned char) find->dl_mac_address[1],
                           (unsigned char) find->dl_mac_address[2],
                           (unsigned char) find->dl_mac_address[3],
                           (unsigned char) find->dl_mac_address[4],
                           (unsigned char) find->dl_mac_address[5]);
                }
                char* mac=find->dl_mac_address;
                float avg = getRssi(find);
                sprintf(buf, "RSSIO;%s;%s;%s;%f;",positionX,positionY,
                      //  mapID,
                        addr,
                      //  (unsigned char) s.ifr_addr.sa_data[0],
                      //  (unsigned char) s.ifr_addr.sa_data[1],
                      //(unsigned char) s.ifr_addr.sa_data[2],
                      //  (unsigned char) s.ifr_addr.sa_data[3],
                      //  (unsigned char) s.ifr_addr.sa_data[4],
                      //  (unsigned char) s.ifr_addr.sa_data[5],
                        avg);
                printf("sent: %s\n", buf);
                sockbw= socket(AF_INET, SOCK_DGRAM, 0);
                if(sockbw<0){
                    perror("Could not open socket\n");
                    exit(1);
                }
                your_addr.sin_family=AF_INET;
                your_addr.sin_port = htons(YOURPORT);
                if(numbytes=sendto(sockfd, buf, MAXBUFLEN, 0, (struct sockaddr *)&your_addr,sizeof(struct sockaddr))<0){
                    perror("sendto");
                    exit(1);
                }
                close(sockbw);
               // pthread_mutex_unlock(&mDeviceList);
            }
            else if(strcmp(cmd, "GET") == 0)
            {
                //////////////////////////////////////online mode
                char* addr = strtok(NULL, ";");
                if(!addr)
                    continue;
                if(strcmp(addr, "null") == 0)
                    continue;
                char mac_addr[6];
                sscanf(addr, "%x:%x:%x:%x:%x:%x",     (int*) &mac_addr[0],
                       (int*) &mac_addr[1],
                       (int*) &mac_addr[2],
                       (int*) &mac_addr[3],
                       (int*) &mac_addr[4],
                       (int*) &mac_addr[5]);
                //pthread_mutex_lock(&mDeviceList);
                DeviceList* find = find_Device(deviceList, mac_addr);
                if(find)
                {
                    printf("> Device Found: %02x:%02x:%02x:%02x:%02x:%02x\n",
                           (unsigned char) find->dl_mac_address[0],
                           (unsigned char) find->dl_mac_address[1],
                           (unsigned char) find->dl_mac_address[2],
                           (unsigned char) find->dl_mac_address[3],
                           (unsigned char) find->dl_mac_address[4],
                           (unsigned char) find->dl_mac_address[5]);
                }
                float avg = getRssi(find);
                sprintf(buf, "RSS;%s;%f;",
                        addr,
                       // (unsigned char) s.ifr_addr.sa_data[0],
                       // (unsigned char) s.ifr_addr.sa_data[1],
                       // (unsigned char) s.ifr_addr.sa_data[2],
                       // (unsigned char) s.ifr_addr.sa_data[3],
                       // (unsigned char) s.ifr_addr.sa_data[4],
                        //(unsigned char) s.ifr_addr.sa_data[5],
                        avg);
                printf("sent: %s\n", buf);
                sockbw= socket(AF_INET, SOCK_DGRAM, 0);
                if(sockbw<0){
                    perror("Could not open socket\n");
                    exit(1);
                }
                your_addr.sin_family=AF_INET;
                your_addr.sin_port = htons(YOURPORT);
                if(numbytes=sendto(sockfd, buf, MAXBUFLEN, 0, (struct sockaddr *)&your_addr,sizeof(struct sockaddr))<0){
                    perror("sendto");
                    exit(1);
                }
                close(sockbw);
                //pthread_mutex_unlock(&mDeviceList);
            }
            
        }
        close(sockfd);
    }
}
///////////////////////////////////////////////////////////
    static void *rssi_listening(void *ptr){
    const u_char* packet;
    DeviceList **devicelist=NULL;
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    dev="prism0"; // interface to sniff on
    handle=pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);//opens the device stored in the strong "dev", tells it to read however many bytes are specified in BUFSIZ (which is defined in pcap.h). We are telling it to put the device into promiscuous mode, to sniff until an error occurs, and if there is an error, store it in the string errbuf; it uses that string to print an error message.
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    while(1){
        packet=pcap_next(handle, &header);
        if(((unsigned int *) packet)[0] == 0x41)
        {
            ph = (struct prism_header *) packet;
            eh = (struct ieee80211_header *) (packet+ph->msglen);
            // Check if FromDS flag equals 0
            if((eh->frame_control & 0xc0) == 0x80)
            {
                DeviceList* currentDevice = 0;
              //  pthread_mutex_lock(&mDeviceList);
                // find this Device in our List
                currentDevice = find_Device(deviceList, eh->source_addr);
                // this device doesn't exist ?
               if(!currentDevice)
                {
                  //  currentDevice = add_device(&deviceList, eh->source_addr);
                    printf("Device created: %02x:%02x:%02x:%02x:%02x:%02x\n",
                           eh->source_addr[0],
                           eh->source_addr[1],
                           eh->source_addr[2],
                           eh->source_addr[3],
                           eh->source_addr[4],
                           eh->source_addr[5]);
                }
                // add a new sample.
              // add_rssi_sample(currentDevice, (ph->rssi).data);
            //    pthread_mutex_unlock(&mDeviceList);
    }
}
}
    }
 ///////////////////////////////////////////////////////////
        int main(int argc,char *argv[])
        {
            deviceList=0;
            pthread_t rssi_thread,udp_thread;
           // int rssi_th_id, udp_th_id;
            char * mess_rssi = "RSSI";
            char * mess_udp ="UDP";
            int * my_ret = 0;
            pthread_create(&udp_thread, NULL, udp_listening, (void*)mess_udp);
            pthread_create(&rssi_thread, NULL, rssi_listening, (void*)mess_rssi);
            pthread_join(udp_thread,NULL);
            pthread_join(rssi_thread, NULL);
            printf("%d",*my_ret);
            return(0);
        
        }
    
