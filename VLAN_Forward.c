
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* Ethernet switch configuration */
#define NPORTS          4
#define FDB_SIZE        256
#define MAC_LEN         6
#define ETH_HDR_LEN     14
#define VLAN_HDR_LEN    18

#define VLAN_TPID       0x8100
#define VLAN_ID_MASK    0x0FFF
#define VLAN_MIN        1
#define VLAN_MAX        4094

#define MAC_AGE_MS      60000ULL
#define MAX_FRAME_LEN   65535

/* Provided by harness.c */
struct port_cfg {
    int trunk;
    uint16_t pvid;
    uint16_t allowed[8];
    int n_allowed;
};

extern struct port_cfg port_cfg[NPORTS];

extern void tx(int out_port,
               const uint8_t *frame,
               size_t len);

/* Forwarding database */
struct fdb_entry {
    uint8_t mac[MAC_LEN];
    uint16_t vlan_id;
    int port;
    uint64_t last_seen_ms;
    struct fdb_entry *next;
};

static struct fdb_entry *fdb[FDB_SIZE];

/* Protect FDB operations between multiple threads */
static pthread_mutex_t fdb_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Read 16-bit big-endian value */
static uint16_t read_be16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

/* Write 16-bit big-endian value */
static void write_be16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)(value & 0xFF);
}

/* Compare MAC addresses */
static int mac_equal(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, MAC_LEN) == 0;
}

/* Check valid VLAN ID */
static int valid_vlan(uint16_t vid)
{
    return vid >= VLAN_MIN && vid <= VLAN_MAX;
}

/* Check whether a MAC is multicast/broadcast */
static int is_multicast(const uint8_t *mac)
{
    return (mac[0] & 0x01) != 0;
}

/* Hash MAC address and VLAN ID */
static unsigned int fdb_hash(const uint8_t *mac,
                             uint16_t vlan_id)
{
    uint32_t hash = 2166136261u;

    for (int i = 0; i < MAC_LEN; i++) {
        hash ^= mac[i];
        hash *= 16777619u;
    }

    hash ^= (uint8_t)(vlan_id >> 8);
    hash *= 16777619u;

    hash ^= (uint8_t)vlan_id;
    hash *= 16777619u;

    return hash % FDB_SIZE;
}

/* Check VLAN membership on trunk port */
static int trunk_allows_vlan(int port, uint16_t vid)
{
    if (port < 0 || port >= NPORTS)
        return 0;

    for (int i = 0; i < port_cfg[port].n_allowed; i++) {
        if (port_cfg[port].allowed[i] == vid)
            return 1;
    }

    return 0;
}

/* Check whether a port supports a VLAN */
static int port_allows_vlan(int port, uint16_t vid)
{
    if (port < 0 || port >= NPORTS)
        return 0;

    if (port_cfg[port].trunk)
        return trunk_allows_vlan(port, vid);

    return port_cfg[port].pvid == vid;
}

/* Learn source MAC address */
static void fdb_learn(const uint8_t *mac,
                      uint16_t vlan_id,
                      int port,
                      uint64_t now_ms)
{
    unsigned int index = fdb_hash(mac, vlan_id);

    pthread_mutex_lock(&fdb_mutex);

    struct fdb_entry *entry = fdb[index];

    while (entry != NULL) {

        if (entry->vlan_id == vlan_id &&
            mac_equal(entry->mac, mac)) {

            /* Update port if MAC moved */
            entry->port = port;
            entry->last_seen_ms = now_ms;

            pthread_mutex_unlock(&fdb_mutex);
            return;
        }

        entry = entry->next;
    }

    /* Create new FDB entry */
    entry = malloc(sizeof(*entry));

    if (entry == NULL) {
        pthread_mutex_unlock(&fdb_mutex);
        return;
    }

    memcpy(entry->mac, mac, MAC_LEN);

    entry->vlan_id = vlan_id;
    entry->port = port;
    entry->last_seen_ms = now_ms;

    entry->next = fdb[index];
    fdb[index] = entry;

    pthread_mutex_unlock(&fdb_mutex);
}

/* Look up destination MAC */
static int fdb_lookup(const uint8_t *mac,
                      uint16_t vlan_id,
                      uint64_t now_ms)
{
    unsigned int index = fdb_hash(mac, vlan_id);
    int result = -1;

    pthread_mutex_lock(&fdb_mutex);

    struct fdb_entry *entry = fdb[index];

    while (entry != NULL) {

        if (entry->vlan_id == vlan_id &&
            mac_equal(entry->mac, mac)) {

            if (now_ms >= entry->last_seen_ms &&
                now_ms - entry->last_seen_ms < MAC_AGE_MS) {
                result = entry->port;
            }

            break;
        }

        entry = entry->next;
    }

    pthread_mutex_unlock(&fdb_mutex);

    return result;
}

/* Remove expired FDB entries */
static void fdb_age(uint64_t now_ms)
{
    pthread_mutex_lock(&fdb_mutex);

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

    pthread_mutex_unlock(&fdb_mutex);
}

/*
 * Transmit frame:
 * - Trunk output: add VLAN tag if missing.
 * - Access output: remove VLAN tag if present.
 */
static void transmit_frame(int out_port,
                           const uint8_t *frame,
                           size_t len,
                           int tagged,
                           uint16_t vlan_id,
                           uint16_t vlan_tci)
{
    uint8_t *out_frame;
    size_t out_len;

    /* Check output port VLAN eligibility */
    if (!port_allows_vlan(out_port, vlan_id))
        return;

    /* Trunk port */
    if (port_cfg[out_port].trunk) {

        /* Already tagged: preserve original frame */
        if (tagged) {
            tx(out_port, frame, len);
            return;
        }

        /* Insert VLAN tag */
        out_frame = malloc(len + 4);

        if (out_frame == NULL)
            return;

        uint16_t output_tci = vlan_id;

        memcpy(out_frame, frame, 12);

        write_be16(out_frame + 12, VLAN_TPID);
        write_be16(out_frame + 14, output_tci);

        memcpy(out_frame + 16, frame + 12, len - 12);

        out_len = len + 4;

        tx(out_port, out_frame, out_len);

        free(out_frame);
    }

    /* Access port */
    else {

        /* Already untagged */
        if (!tagged) {
            tx(out_port, frame, len);
            return;
        }

        /* Remove VLAN tag */
        out_frame = malloc(len - 4);

        if (out_frame == NULL)
            return;

        memcpy(out_frame, frame, 12);

        memcpy(out_frame + 12,
               frame + 16,
               len - 16);

        out_len = len - 4;

        tx(out_port, out_frame, out_len);

        free(out_frame);
    }
}

/* Flood frame only within the same VLAN */
static void flood_frame(int in_port,
                        const uint8_t *frame,
                        size_t len,
                        uint16_t vlan_id,
                        int tagged,
                        uint16_t vlan_tci)
{
    for (int port = 0; port < NPORTS; port++) {

        /* Do not send back to ingress port */
        if (port == in_port)
            continue;

        /* Transmit function checks VLAN eligibility */
        transmit_frame(port,
                       frame,
                       len,
                       tagged,
                       vlan_id,
                       vlan_tci);
    }
}

/* Main receive function */
void switch_rx(int in_port,
               const uint8_t *frame,
               size_t len,
               uint64_t now_ms)
{
    uint8_t dst_mac[MAC_LEN];
    uint8_t src_mac[MAC_LEN];

    uint16_t ethertype;
    uint16_t vlan_id;
    uint16_t vlan_tci = 0;

    int tagged = 0;

    /* Validate ingress port */
    if (in_port < 0 || in_port >= NPORTS)
        return;

    /* Validate frame pointer */
    if (frame == NULL)
        return;

    /* Validate Ethernet frame length */
    if (len < ETH_HDR_LEN || len > MAX_FRAME_LEN)
        return;

    /* Extract destination and source MAC */
    memcpy(dst_mac, frame, MAC_LEN);
    memcpy(src_mac, frame + 6, MAC_LEN);

    /* Read EtherType */
    ethertype = read_be16(frame + 12);

    /* Check for 802.1Q VLAN tag */
    if (ethertype == VLAN_TPID) {

        if (len < VLAN_HDR_LEN)
            return;

        tagged = 1;

        vlan_tci = read_be16(frame + 14);

        vlan_id = vlan_tci & VLAN_ID_MASK;

        ethertype = read_be16(frame + 16);

        if (!valid_vlan(vlan_id))
            return;

        /* Access ports reject tagged ingress */
        if (!port_cfg[in_port].trunk)
            return;

        /* Check trunk VLAN membership */
        if (!trunk_allows_vlan(in_port, vlan_id))
            return;
    }
    else {

        /* Trunk ports reject untagged ingress */
        if (port_cfg[in_port].trunk)
            return;

        /* Assign access port PVID */
        vlan_id = port_cfg[in_port].pvid;

        if (!valid_vlan(vlan_id))
            return;
    }

    /* Age old FDB entries */
    fdb_age(now_ms);

    /* Learn source MAC only if unicast */
    if (!is_multicast(src_mac)) {
        fdb_learn(src_mac,
                  vlan_id,
                  in_port,
                  now_ms);
    }

    /* Broadcast or multicast destination: flood */
    if (is_multicast(dst_mac)) {

        flood_frame(in_port,
                    frame,
                    len,
                    vlan_id,
                    tagged,
                    vlan_tci);

        return;
    }

    /* Look up destination MAC in FDB */
    int out_port = fdb_lookup(dst_mac,
                              vlan_id,
                              now_ms);

    /* Unknown destination: flood */
    if (out_port < 0) {

        flood_frame(in_port,
                    frame,
                    len,
                    vlan_id,
                    tagged,
                    vlan_tci);

        return;
    }

    /* Do not forward back to ingress port */
    if (out_port == in_port)
        return;

    /* Forward known unicast */
    transmit_frame(out_port,
                   frame,
                   len,
                   tagged,
                   vlan_id,
                   vlan_tci);
}

