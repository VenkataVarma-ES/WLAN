
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Number of Ethernet ports */
#define NPORTS 4

/* Harness-provided functions and configuration */
extern void tx(int out_port, const uint8_t *frame, size_t len);

struct port_cfg {
    int trunk;
    uint16_t pvid;
    uint16_t allowed[8];
    int n_allowed;
};

extern struct port_cfg port_cfg[NPORTS];

/* Ethernet header length */
#define ETH_HEADER_LEN 14

/* Print MAC address */
static void print_mac(const uint8_t mac[6])
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}

/* Read 16-bit network byte order value */
static uint16_t read_be16(const uint8_t *data)
{
    return ((uint16_t)data[0] << 8) | data[1];
}

/* Stage 1: Receive and parse Ethernet frame */
void switch_rx(int in_port,
               const uint8_t *frame,
               size_t len,
               uint64_t now_ms)
{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;

    (void)now_ms;

    /* Validate ingress port */
    if (in_port < 0 || in_port >= NPORTS) {
        printf("Invalid ingress port: %d\n", in_port);
        return;
    }

    /* Validate frame pointer */
    if (frame == NULL) {
        printf("NULL frame received on port %d\n", in_port);
        return;
    }

    /* Validate minimum Ethernet header length */
    if (len < ETH_HEADER_LEN) {
        printf("Malformed frame: length=%zu port=%d\n",
               len, in_port);
        return;
    }

    /* Extract destination MAC */
    memcpy(dst_mac, frame, 6);

    /* Extract source MAC */
    memcpy(src_mac, frame + 6, 6);

    /* Extract EtherType (network byte order) */
    ethertype = read_be16(frame + 12);

    /* Display parsed Ethernet information */
    printf("Ingress Port : %d\n", in_port);

    printf("Source MAC   : ");
    print_mac(src_mac);
    printf("\n");

    printf("Dest MAC     : ");
    print_mac(dst_mac);
    printf("\n");

    printf("EtherType    : 0x%04X\n", ethertype);

    printf("----------------------------------\n");
}

