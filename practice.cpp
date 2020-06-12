#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<assert.h>
#include<unistd.h>
#include<stdint.h>
#include<string.h>
#include<errno.h>

#define QTYPE_A 1
#define QCLASS_IN 1

struct DnsHeader
{
    uint16_t id;
    uint16_t flag;
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
};

void sendQuery(int fd)
{
    char buff[512];
    DnsHeader* header=(DnsHeader*)buff;
    char*buffP=buff+sizeof(DnsHeader);
    header->id=htons(11);
    header->flag=htons(0b0000000100000000);
    header->qd_count=htons(1);
    header->an_count=0;
    header->ns_count=0;
    header->ar_count=0;

    //buffP+=sprintf(buffP,"\6libtec\3org")+1;
    uint8_t a1=2;
    uint8_t a2=0;
    uint8_t a3=0;
    uint8_t a4=127;
    *buffP=1;
    ++buffP;
    buffP+=sprintf(buffP,"%u",a1);
    *buffP=1;
    ++buffP;
    buffP+=sprintf(buffP,"%u",a2);
    *buffP=1;
    ++buffP;
    buffP+=sprintf(buffP,"%u",a3);
    *buffP=3;
    ++buffP;
    buffP+=sprintf(buffP,"%u",a4);
    *buffP=3;
    ++buffP;
    buffP+=sprintf(buffP,"zen");
    *buffP=8;
    ++buffP;
    buffP+=sprintf(buffP,"spamhaus");
    *buffP=3;
    ++buffP;
    buffP+=sprintf(buffP,"org");
    ++buffP;
    
    uint16_t* q_type=(uint16_t*)buffP;
    buffP+=sizeof(uint16_t);
    uint16_t* q_class=(uint16_t*)buffP;
    buffP+=sizeof(uint16_t);
    *q_type=htons(QTYPE_A);
    *q_class=htons(QCLASS_IN);
    
    printf("size: %lu\n",buffP-buff);    
    for (int i = 0; i < buffP-buff; i++)
    {
        printf("%02x ",(uint8_t)buff[i]);
    }
    printf("\n");
    write(fd,buff,(buffP-buff));
}
char* labelRec(char*buff,char* buffP)
{
    while (true)
    {
        unsigned char labelLen=(*buffP);
        //printf("labelLen: %02x %d\n",labelLen,labelLen);
        ++buffP;
        if (labelLen==0)
        {
            break;
        }
        else if (labelLen>>6==0b11)
        {
            int offset=((labelLen&0b111111)<<8)&(*buffP);
            //printf("offset: %02x  %d\n",offset,offset);
            labelRec(buff,buff+offset);
            ++buffP;
            break;
        }
        else
        {
            printf("%.*s^",labelLen,buffP);
            //printf("\nlabelLen: %02x %d\n",labelLen,labelLen);
            buffP+=labelLen;
        }
    }
    return buffP;
}

char* printRecord(char*buff,char*buffP)
{
    buffP=labelRec(buff,buffP);
    printf("\n");
    uint16_t qType=ntohs(*((uint16_t*)buffP));
    buffP+=sizeof(uint16_t);
    uint16_t qClass=ntohs(*((uint16_t*)buffP));
    buffP+=sizeof(uint16_t);
    printf("qType: %u\n",qType);
    printf("qClass: %u\n",qClass);
    assert(qType==QTYPE_A);
    assert(qClass==QCLASS_IN);
    uint32_t ttl=ntohl(*((uint32_t*)buffP));
    printf("TTL: %u\n",ttl);
    buffP+=sizeof(uint32_t);
    uint16_t rdLen=ntohs(*((uint16_t*)buffP));
    printf("rdLen: %u\n",rdLen);
    buffP+=sizeof(uint16_t);
    uint8_t addr1=*buffP;
    buffP+=sizeof(uint8_t);
    uint8_t addr2=*buffP;
    buffP+=sizeof(uint8_t);
    uint8_t addr3=*buffP;
    buffP+=sizeof(uint8_t);
    uint8_t addr4=*buffP;
    buffP+=sizeof(uint8_t);
    printf("RDATA: %u.%u.%u.%u\n",addr1,addr2,addr3,addr4);

    return buffP;
}

void recoverResponse(int fd)
{
    char buff[512];
    ssize_t readStatus=read(fd,buff,sizeof(buff));
    if (readStatus==-1)
    {
        fprintf(stderr,"Error: %s\n",strerror(errno));
        return;
    }
    int responseLen=readStatus;
    assert(responseLen);
    printf("Length: %d\n",responseLen);
    for (int i = 0; i < responseLen; i++)
    {
        printf("%02x ",(uint8_t)buff[i]);
    }
    printf("\n");

    DnsHeader* header=(DnsHeader*)buff;
    header->id=ntohs(header->id);
    header->flag=ntohs(header->flag);
    header->qd_count=ntohs(header->qd_count);
    header->an_count=ntohs(header->an_count);
    header->ns_count=ntohs(header->ns_count);
    header->ar_count=ntohs(header->ar_count);
    //assert(header->flag==0x8080);
    if (header->flag!=0x8080&&header->flag!=0x8180)
    {
        int rCode=header->flag&0b1111;
        switch (rCode)
        {
        case 1:
            printf("Format error\n");
            break;
        case 2:
            printf("Server failure\n");
            break;
        case 3:
            printf("Name Error\n");
            break;
        case 4:
            printf("Not implemented\n");
            break;
        case 5:
            printf("Refused\n");
            break;
        default:
            break;
        }
    }
    char* buffP=buff+sizeof(DnsHeader);
    printf("QDCOUNT\n");
    for (int i = 0; i < header->qd_count; i++)
    {
        buffP=labelRec(buff,buffP);
        printf("\n");
        uint16_t qType=ntohs(*((uint16_t*)buffP));
        buffP+=sizeof(uint16_t);
        uint16_t qClass=ntohs(*((uint16_t*)buffP));
        buffP+=sizeof(uint16_t);
        assert(qType==QTYPE_A);
        assert(qClass==QCLASS_IN);
    }
    printf("ANCOUNT\n");
    for (int i = 0; i < header->an_count; i++)
    {
        buffP=printRecord(buff,buffP);
    }
    printf("\nName servers\n");    
    for (int i = 0; i < header->ns_count; i++)
    {
        buffP=printRecord(buff,buffP);
    }
    printf("\nARCOUNT:\n");
    for (int i = 0; i < header->ar_count; i++)
    {
        buffP=printRecord(buff,buffP);
    }
    
}



void readWithLables(char*buffP,char*buff)
{
    while (true)
    {
        int labelLen=(*buffP);
        if (labelLen==0)
        {
            break;
        }
        else if (labelLen>>6==0b11)
        {
            int offset=((labelLen&0b111111)<<8)&(*buffP);
            readWithLables(buff+offset,buff);
        }
        printf("%.*s.",labelLen,buffP);
        buffP+=labelLen;
    }
    
}

int main(int argc,char*argv[])
{
   if (argc != 2) {
        fprintf(stderr, "%s <dotted-address>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    struct in_addr addr;

    if (inet_aton(argv[1], &addr) == 0) {
        fprintf(stderr, "Invalid address\n");
        exit(EXIT_FAILURE);
    }

/*     int a=addr.s_addr&0xff;
    int b=(addr.s_addr>>8)&0xff;
    int c=(addr.s_addr>>16)&0xff;
    int d=(addr.s_addr>>24)&0xff; */

    //char buff[512];
    //sprintf(buff,"%d.%d.%d.%d.zen.spamhaus.org.",d,c,b,a);//.??
    int fd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    struct sockaddr_in dns_addr;
    dns_addr.sin_family=AF_INET;
    dns_addr.sin_port=htons(53);
    inet_aton("8.8.8.8",&dns_addr.sin_addr);
    //inet_aton("192.168.0.1",&dns_addr.sin_addr);
    //inet_aton("127.0.0.1",&dns_addr.sin_addr);

    int connect_error=connect(fd,(struct sockaddr*)&dns_addr,sizeof(dns_addr));
    assert(!connect_error);

    sendQuery(fd);
    recoverResponse(fd);

    //sprintf(buff,"%d.%d.%d.%d.zen.spamhaus.org.",d,c,b,a);
    
    close(fd);
}