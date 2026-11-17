/*
 * harness.c — miniswitch development harness (given to the candidate)
 *
 * Build:  gcc -Wall -Wextra -O1 -pthread harness.c yourcode.c -o miniswitch
 * Run:    ./miniswitch        sample checks (sanity only — see note below)
 *         ./miniswitch 4      Stage 4 stress (4 injector threads; build with
 *                             -fsanitize=thread or address to surface races)
 *
 * You implement switch_rx() and call tx() to transmit.
 * Time is simulated: the only clock is the now_ms passed into switch_rx().
 *
 * NOTE: the sample checks below are a smoke test, not the grading set.
 * Grading runs a larger private test set covering exactly the behaviors
 * described in the brief (learning, flooding, filtering, station moves,
 * aging, VLAN tagging rules, malformed frames). Passing the samples does
 * not mean you are done — implement the brief, and add your own cases
 * here to convince yourself (doing so is encouraged and looked on well).
 */
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NPORTS 4

/* ---- contract: implemented by the candidate ---- */
void switch_rx(int in_port, const uint8_t *frame, size_t len, uint64_t now_ms);

/* ---- per-port VLAN config (read this from Stage 3 on) ---- */
struct port_cfg {
    int trunk;            /* 0 = access, 1 = trunk */
    uint16_t pvid;        /* access: VLAN assigned to untagged ingress */
    uint16_t allowed[8];  /* trunk: permitted VIDs */
    int n_allowed;
};
struct port_cfg port_cfg[NPORTS];

static void cfg_flat(void) /* Stages 1/2/4: every port access, VLAN 1 */
{
    for (int i = 0; i < NPORTS; i++)
        port_cfg[i] = (struct port_cfg){ .trunk = 0, .pvid = 1 };
}

static void cfg_vlan(void) /* Stage 3: 0,1 access 10; 2 access 20; 3 trunk {10,20} */
{
    port_cfg[0] = (struct port_cfg){ .trunk = 0, .pvid = 10 };
    port_cfg[1] = (struct port_cfg){ .trunk = 0, .pvid = 10 };
    port_cfg[2] = (struct port_cfg){ .trunk = 0, .pvid = 20 };
    port_cfg[3] = (struct port_cfg){ .trunk = 1, .allowed = {10, 20}, .n_allowed = 2 };
}

/* ---- TX recording (atomics so the stress run is race-free) ---- */
static _Atomic int tx_count[NPORTS];
static _Atomic int tx_tagged[NPORTS]; /* last frame on this port had an 802.1Q tag */
static _Atomic int tx_bad;

void tx(int out_port, const uint8_t *frame, size_t len)
{
    if (out_port < 0 || out_port >= NPORTS) { atomic_fetch_add(&tx_bad, 1); return; }
    atomic_fetch_add(&tx_count[out_port], 1);
    atomic_store(&tx_tagged[out_port],
                 len >= 14 && frame[12] == 0x81 && frame[13] == 0x00);
}

/* builds dst|src|[802.1Q tag]|ethertype|46-byte payload; vid -1 = untagged */
size_t mkframe(uint8_t *b, const uint8_t dst[6], const uint8_t src[6],
               int vid, uint16_t ethertype)
{
    size_t off = 12;
    memcpy(b, dst, 6);
    memcpy(b + 6, src, 6);
    if (vid >= 0) {
        b[off++] = 0x81; b[off++] = 0x00;
        b[off++] = (uint8_t)((vid >> 8) & 0x0F);
        b[off++] = (uint8_t)(vid & 0xFF);
    }
    b[off++] = (uint8_t)(ethertype >> 8);
    b[off++] = (uint8_t)(ethertype & 0xFF);
    memset(b + off, 0xAB, 46);
    return off + 46;
}

/* ---- case checker ---- */
static int failures;

static void expect(const char *name, const int want_cnt[NPORTS],
                   const int want_tag[NPORTS])
{
    int ok = atomic_load(&tx_bad) == 0;
    for (int i = 0; i < NPORTS; i++) {
        int c = atomic_load(&tx_count[i]);
        if (c != want_cnt[i]) ok = 0;
        if (want_tag && want_cnt[i] && atomic_load(&tx_tagged[i]) != want_tag[i]) ok = 0;
    }
    printf("%-52s %s  (TX:", name, ok ? "PASS" : "FAIL");
    for (int i = 0; i < NPORTS; i++)
        printf(" p%d=%d%s", i, atomic_load(&tx_count[i]),
               atomic_load(&tx_count[i]) && atomic_load(&tx_tagged[i]) ? "T" : "");
    printf("%s)\n", atomic_load(&tx_bad) ? " INVALID-PORT" : "");
    if (!ok) failures++;
    for (int i = 0; i < NPORTS; i++) {
        atomic_store(&tx_count[i], 0);
        atomic_store(&tx_tagged[i], 0);
    }
    atomic_store(&tx_bad, 0);
}

static const uint8_t A[6]  = {2,0,0,0,0,1};
static const uint8_t B[6]  = {2,0,0,0,0,2};
static const uint8_t C[6]  = {2,0,0,0,0,3};
static const uint8_t BC[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

static void samples(void)
{
    uint8_t f[1600]; size_t n;
    puts("== sample checks (smoke test only — grading uses a larger private set) ==");
    cfg_flat();
    n = mkframe(f, BC, A, -1, 0x0806); switch_rx(0, f, n, 0);
    expect("s1 bcast from A@0 floods to 1,2,3", (int[]){0,1,1,1}, NULL);
    n = mkframe(f, A, B, -1, 0x0800); switch_rx(1, f, n, 1000);
    expect("s2 B@1 -> A goes to port 0 only (learned)", (int[]){1,0,0,0}, NULL);
    cfg_vlan();
    n = mkframe(f, BC, C, -1, 0x0806); switch_rx(2, f, n, 2000);
    expect("s3 C@2 bcast in VLAN 20: tagged on 3 only",
           (int[]){0,0,0,1}, (int[]){0,0,0,1});
}

/* ---- Stage 4: concurrent stress ---- */
#include <pthread.h>

static _Atomic uint64_t sim_clock_ms = 300000;
#define STRESS_FRAMES 200000

static void *injector(void *arg)
{
    int port = (int)(intptr_t)arg;
    uint8_t f[1600];
    uint8_t src[6] = {2,0,0,0,1,0}, dst[6] = {2,0,0,0,1,0};
    uint32_t seed = 0x1234u + (uint32_t)port;
    for (int i = 0; i < STRESS_FRAMES; i++) {
        seed = seed * 1103515245u + 12345u;
        src[5] = (uint8_t)((seed >> 16) % 8);
        seed = seed * 1103515245u + 12345u;
        dst[5] = (uint8_t)((seed >> 16) % 8);
        int bcast = ((seed >> 8) % 16) == 0;
        size_t n = mkframe(f, bcast ? BC : dst, src, -1, 0x0800);
        switch_rx(port, f, n, atomic_fetch_add(&sim_clock_ms, 1));
    }
    return NULL;
}

static void stage4(void)
{
    pthread_t t[NPORTS];
    cfg_flat();
    printf("== Stage 4: %d frames from %d concurrent injector threads ==\n",
           STRESS_FRAMES * NPORTS, NPORTS);
    for (int i = 0; i < NPORTS; i++)
        pthread_create(&t[i], NULL, injector, (void *)(intptr_t)i);
    for (int i = 0; i < NPORTS; i++)
        pthread_join(t[i], NULL);
    puts("stress finished without crash — now trust the sanitizer output above");
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "sample";
    if      (!strcmp(mode, "sample")) samples();
    else if (!strcmp(mode, "4"))      stage4();
    else { fprintf(stderr, "usage: %s [sample|4]\n", argv[0]); return 2; }
    if (failures) { printf("\n%d sample(s) FAILED\n", failures); return 1; }
    puts("\nsamples passed — now add your own cases and implement the full brief");
    return 0;
}
