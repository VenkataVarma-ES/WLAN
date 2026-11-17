
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define NPORTS       4
#define FDB_SIZE     256
#define MAC_LEN      6
#define ETH_HDR_LEN  14
#define MAC_AGE_MS   60000ULL

/* Set to 1 to enable packet-level debug prints */
#define DEBUG_FRAMES 0

/* Provided by harness.c */
extern void tx(int out_port, const uint8_t *frame, size_t len);

/* FDB entry */
struct fdb_entry {
    uint8_t mac[MAC_LEN];
    int port;
    uint64_t last_seen_ms;
    struct fdb_entry *next;
};

/* Hash table */
static struct fdb_entry *fdb[FDB_SIZE];

/* Convert network byte order */
static uint16_t read_be16(const uint8_t *data)
{
    return ((uint16_t)data[0] << 8) | data[1];
}

/* Compare MAC addresses */
static int mac_equal(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, MAC_LEN) == 0;
}

/* Print MAC address */
static void print_mac(const uint8_t mac[MAC_LEN])
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}

/* Hash function: FNV-1a */
static unsigned int mac_hash(const uint8_t mac[MAC_LEN])
{
    unsigned int hash = 2166136261u;

    for (int i = 0; i < MAC_LEN; i++) {
        hash ^= mac[i];
        hash *= 16777619u;
    }

    return hash % FDB_SIZE;
}

/* Learn source MAC address */
static void fdb_learn(const uint8_t mac[MAC_LEN],
                      int port,
                      uint64_t now_ms)
{
    unsigned int index = mac_hash(mac);

    struct fdb_entry *entry = fdb[index];

    while (entry != NULL) {

        if (mac_equal(entry->mac, mac)) {

            /* Update port if station moved */
            entry->port = port;
            entry->last_seen_ms = now_ms;

            return;
        }

        entry = entry->next;
    }

    /* Create new FDB entry */
    entry = malloc(sizeof(*entry));

    if (entry == NULL) {
        fprintf(stderr, "FDB allocation failed\n");
        return;
    }

    memcpy(entry->mac, mac, MAC_LEN);

    entry->port = port;
    entry->last_seen_ms = now_ms;

    entry->next = fdb[index];
    fdb[index] = entry;
}

/* Lookup destination MAC */
static struct fdb_entry *fdb_lookup(const uint8_t mac[MAC_LEN],
                                    uint64_t now_ms)
{
    unsigned int index = mac_hash(mac);

    struct fdb_entry *entry = fdb[index];

    while (entry != NULL) {

        if (mac_equal(entry->mac, mac)) {

            /* Check whether entry expired */
            if (now_ms >= entry->last_seen_ms &&
                now_ms - entry->last_seen_ms >= MAC_AGE_MS) {
                return NULL;
            }

            return entry;
        }

        entry = entry->next;
    }

    return NULL;
}

/* Remove expired FDB entries */
static void fdb_age(uint64_t now_ms)
{
    for (int i = 0; i < FDB_SIZE; i++) {

        struct fdb_entry **current = &fdb[i];

        while (*current != NULL) {

            struct fdb_entry *entry = *current;

            if (now_ms >= entry->last_seen_ms &&
                now_ms - entry->last_seen_ms >= MAC_AGE_MS) {

                *current = entry->next;

                free(entry);
            }
            else {
                current = &entry->next;
            }
        }
    }
}

/* Display complete forwarding database */
void fdb_dump(void)
{
    printf("\n========== FDB TABLE ==========\n");

    for (int i = 0; i < FDB_SIZE; i++) {

        struct fdb_entry *entry = fdb[i];

        while (entry != NULL) {

            printf("MAC: ");
            print_mac(entry->mac);

            printf(" | Port: %d", entry->port);

            printf(" | Last Seen: %llu ms\n",
                   (unsigned long long)entry->last_seen_ms);

            entry = entry->next;
        }
    }

    printf("===============================\n");
}

/* Check whether destination is multicast/broadcast */
static int is_multicast(const uint8_t mac[MAC_LEN])
{
    return (mac[0] & 0x01) != 0;
}

/* Flood frame to all ports except ingress */
static void flood_frame(int in_port,
                        const uint8_t *frame,
                        size_t len)
{
    for (int port = 0; port < NPORTS; port++) {

        if (port != in_port) {
            tx(port, frame, len);
        }
    }
}

/* Stage 1 + Stage 2: Receive, learn and forward */
void switch_rx(int in_port,
               const uint8_t *frame,
               size_t len,
               uint64_t now_ms)
{
    uint8_t dst_mac[MAC_LEN];
    uint8_t src_mac[MAC_LEN];

    uint16_t ethertype;

    /* Validate ingress port */
    if (in_port < 0 || in_port >= NPORTS) {
        return;
    }

    /* Validate frame pointer */
    if (frame == NULL) {
        return;
    }

    /* Validate minimum Ethernet header */
    if (len < ETH_HDR_LEN) {
        return;
    }

    /* Extract Ethernet fields */
    memcpy(dst_mac, frame, MAC_LEN);
    memcpy(src_mac, frame + MAC_LEN, MAC_LEN);

    ethertype = read_be16(frame + 12);

#if DEBUG_FRAMES
    printf("\nIngress Port: %d\n", in_port);

    printf("Source MAC: ");
    print_mac(src_mac);

    printf("\nDestination MAC: ");
    print_mac(dst_mac);

    printf("\nEtherType: 0x%04X\n", ethertype);
#endif

    (void)ethertype;

    /* Remove expired entries */
    fdb_age(now_ms);

    /* Learn source MAC address */
    fdb_learn(src_mac, in_port, now_ms);

    /*
     * Broadcast and multicast:
     * Flood to every port except ingress.
     */
    if (is_multicast(dst_mac)) {

        flood_frame(in_port, frame, len);

        return;
    }

    /*
     * Unicast:
     * Search destination MAC in FDB.
     */
    struct fdb_entry *entry = fdb_lookup(dst_mac, now_ms);

    if (entry != NULL) {

        /* Never transmit back to ingress port */
        if (entry->port != in_port) {

            tx(entry->port, frame, len);
        }
    }
    else {

        /* Unknown unicast: flood */
        flood_frame(in_port, frame, len);
    }
}

