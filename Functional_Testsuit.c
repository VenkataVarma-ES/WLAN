/* Extra functional tests for mytest3.c; compile WITHOUT harness.c. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define NPORTS 4
#define MAX_CAPTURE 32
#define MAX_BYTES 256

struct port_cfg {
    int trunk;
    uint16_t pvid;
    uint16_t allowed[8];
    int n_allowed;
};
struct port_cfg port_cfg[NPORTS];

extern void switch_rx(int in_port, const uint8_t *frame, size_t len, uint64_t now_ms);

struct captured {
    int port;
    size_t len;
    uint8_t data[MAX_BYTES];
};
static struct captured sent[MAX_CAPTURE];
static int sent_count;
static int failures;

void tx(int port, const uint8_t *frame, size_t len)
{
    if (sent_count >= MAX_CAPTURE || len > MAX_BYTES || port < 0 || port >= NPORTS) {
        fprintf(stderr, "Unexpected tx(port=%d,len=%zu)\n", port, len);
        failures++;
        return;
    }
    sent[sent_count].port = port;
    sent[sent_count].len = len;
    memcpy(sent[sent_count].data, frame, len);
    sent_count++;
}

static void clear_tx(void) { sent_count = 0; }
static void flat_config(void)
{
    memset(port_cfg, 0, sizeof(port_cfg));
    for (int i = 0; i < NPORTS; i++) port_cfg[i].pvid = 10;
}
static void vlan_config(void)
{
    flat_config();
    port_cfg[2].pvid = 20;
    port_cfg[3].trunk = 1;
    port_cfg[3].n_allowed = 2;
    port_cfg[3].allowed[0] = 10;
    port_cfg[3].allowed[1] = 20;
}

/* Builds a 60-byte Ethernet frame, or a 64-byte tagged frame. */
static size_t make_frame(uint8_t *buf, const uint8_t dst[6],
                         const uint8_t src[6], int tagged, uint16_t tci)
{
    size_t len = tagged ? 64 : 60;
    memset(buf, 0, len);
    memcpy(buf, dst, 6);
    memcpy(buf + 6, src, 6);
    if (tagged) {
        buf[12] = 0x81; buf[13] = 0x00;
        buf[14] = (uint8_t)(tci >> 8);
        buf[15] = (uint8_t)tci;
        buf[16] = 0x08; buf[17] = 0x00;
    } else {
        buf[12] = 0x08; buf[13] = 0x00;
    }
    return len;
}

static int has_port(int port)
{
    for (int i = 0; i < sent_count; i++)
        if (sent[i].port == port) return 1;
    return 0;
}
static const struct captured *at_port(int port)
{
    for (int i = 0; i < sent_count; i++)
        if (sent[i].port == port) return &sent[i];
    return NULL;
}
static void check(const char *name, int ok)
{
    printf("%-58s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) failures++;
}

int main(void)
{
    static const uint8_t bc[6] = {255,255,255,255,255,255};
    static const uint8_t a[6]  = {0x02,0,0,0,0,0x11};
    static const uint8_t b[6]  = {0x02,0,0,0,0,0x12};
    static const uint8_t c[6]  = {0x02,0,0,0,0,0x13};
    static const uint8_t d[6]  = {0x02,0,0,0,0,0x14};
    static const uint8_t e[6]  = {0x02,0,0,0,0,0x15};
    static const uint8_t f[6]  = {0x02,0,0,0,0,0x16};
    uint8_t frame[128];
    size_t len;
    const struct captured *pkt;
    uint64_t t = 100000;

    flat_config();
    len = make_frame(frame, bc, a, 0, 0);
    clear_tx(); switch_rx(0, frame, len, t++);
    check("1. Flat broadcast floods to other 3 ports", sent_count == 3 &&
          has_port(1) && has_port(2) && has_port(3) && !has_port(0));

    len = make_frame(frame, a, b, 0, 0);
    clear_tx(); switch_rx(1, frame, len, t++);
    check("2. Learned unicast goes only to port 0", sent_count == 1 && has_port(0));

    len = make_frame(frame, a, b, 0, 0);
    clear_tx(); switch_rx(0, frame, len, t++);
    check("3. Destination on ingress port is filtered", sent_count == 0);

    len = make_frame(frame, bc, a, 0, 0);
    clear_tx(); switch_rx(2, frame, len, t++); /* A moves from 0 to 2 */
    len = make_frame(frame, a, c, 0, 0);
    clear_tx(); switch_rx(1, frame, len, t++);
    check("4. MAC movement updates destination port", sent_count == 1 && has_port(2));

    len = make_frame(frame, bc, d, 0, 0);
    clear_tx(); switch_rx(0, frame, len, t++); /* Learn D */
    len = make_frame(frame, d, e, 0, 0);
    clear_tx(); switch_rx(1, frame, len, t + 60001);
    check("5. MAC ages out after 60 seconds (unknown floods)",
          sent_count == 3 && has_port(0) && has_port(2) && has_port(3));
    t += 60003;

    vlan_config();
    len = make_frame(frame, bc, a, 0, 0);
    clear_tx(); switch_rx(0, frame, len, t++);
    pkt = at_port(3);
    check("6. VLAN10 broadcast -> access1 and tagged trunk3",
          sent_count == 2 && has_port(1) && pkt && pkt->len == len + 4 &&
          pkt->data[12] == 0x81 && pkt->data[13] == 0x00 &&
          pkt->data[14] == 0 && pkt->data[15] == 10);

    len = make_frame(frame, bc, b, 0, 0);
    clear_tx(); switch_rx(2, frame, len, t++);
    pkt = at_port(3);
    check("7. VLAN20 broadcast -> tagged trunk3 only",
          sent_count == 1 && pkt && pkt->len == len + 4 &&
          pkt->data[12] == 0x81 && pkt->data[13] == 0x00 &&
          pkt->data[14] == 0 && pkt->data[15] == 20);

    len = make_frame(frame, bc, c, 1, 20);
    clear_tx(); switch_rx(3, frame, len, t++);
    pkt = at_port(2);
    check("8. Tagged VLAN20 trunk ingress -> untagged access2",
          sent_count == 1 && pkt && pkt->len == len - 4 &&
          pkt->data[12] == 0x08 && pkt->data[13] == 0x00);

    len = make_frame(frame, bc, d, 1, 10);
    clear_tx(); switch_rx(3, frame, len, t++);
    check("9. Tagged VLAN10 trunk ingress -> access0 and 1",
          sent_count == 2 && has_port(0) && has_port(1) &&
          at_port(0)->len == len - 4 && at_port(1)->len == len - 4);

    len = make_frame(frame, bc, e, 1, 30);
    clear_tx(); switch_rx(3, frame, len, t++);
    check("10. Disallowed VLAN30 on trunk is dropped", sent_count == 0);

    len = make_frame(frame, bc, e, 1, 20);
    clear_tx(); switch_rx(2, frame, len, t++);
    check("11. Tagged frame on access port is dropped", sent_count == 0);

    len = make_frame(frame, bc, e, 0, 0);
    clear_tx(); switch_rx(3, frame, len, t++);
    check("12. Untagged frame on trunk is dropped", sent_count == 0);

    len = make_frame(frame, bc, e, 1, 0);
    clear_tx(); switch_rx(3, frame, len, t++);
    check("13. VLAN ID 0 is rejected", sent_count == 0);

    len = make_frame(frame, bc, e, 1, 4095);
    clear_tx(); switch_rx(3, frame, len, t++);
    check("14. Reserved VLAN ID 4095 is rejected", sent_count == 0);

    len = make_frame(frame, bc, e, 0, 0);
    clear_tx(); switch_rx(0, frame, 13, t++);
    check("15. Short Ethernet header is dropped", sent_count == 0);

    len = make_frame(frame, bc, e, 1, 20);
    clear_tx(); switch_rx(3, frame, 17, t++);
    check("16. Truncated VLAN header is dropped", sent_count == 0);

    clear_tx(); switch_rx(-1, frame, len, t++);
    switch_rx(4, frame, len, t++);
    switch_rx(0, NULL, len, t++);
    check("17. Invalid port and NULL frame are dropped", sent_count == 0);

    /* Same destination MAC, but learned separately in VLAN10 and VLAN20. */
    len = make_frame(frame, bc, f, 0, 0);
    clear_tx(); switch_rx(0, frame, len, t++); /* F -> port0 VLAN10 */
    len = make_frame(frame, bc, f, 0, 0);
    clear_tx(); switch_rx(2, frame, len, t++); /* F -> port2 VLAN20 */
    len = make_frame(frame, f, a, 0, 0);
    clear_tx(); switch_rx(1, frame, len, t++);
    int vlan10_ok = sent_count == 1 && has_port(0);
    len = make_frame(frame, f, c, 1, 20);
    clear_tx(); switch_rx(3, frame, len, t++);
    check("18. Same MAC has independent FDB entries per VLAN",
          vlan10_ok && sent_count == 1 && has_port(2));

    len = make_frame(frame, e, a, 0, 0);
    clear_tx(); switch_rx(2, frame, len, t++);
    check("19. Unknown VLAN20 unicast floods only to trunk3",
          sent_count == 1 && has_port(3));

    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}

