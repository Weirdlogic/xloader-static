/* Brute-force the 32-bit mask of stage-5 egg-wrapped functions (static; no sample code is executed).
   key = BASE (5 dwords) ^ mask; cipher = passA, passB, RC4(key), passA, passB (subtract mode), as in
   tools/fb_cipher.py. A mask is reported when the decrypted 6-byte start egg equals one of the 0x20
   six-byte windows following the wrapped target. Usage: fb_eggbf <input> <lo_hex> <hi_hex>
   Input line: name c34 start_ct_hex win0 ... win31   (c34 is echoed so c60 = mask^c34^0xdf20ff20) */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAXW 32
#define NWIN 32
static const uint32_t BASE[5] = {0x35b98505, 0xf21dfceb, 0xae10be3a, 0xdd719b86, 0xd5d4d340};
static char name[MAXW][64]; static uint32_t c34[MAXW];
static uint8_t ct[MAXW][6]; static uint8_t win[MAXW][NWIN][6]; static int nw;

static void hex6(const char *s, uint8_t *o) { for (int i = 0; i < 6; i++) sscanf(s + 2 * i, "%2hhx", &o[i]); }

static void undiff(uint8_t *d) {           /* passA (backwards) then passB (forwards), subtract */
    for (int i = 1; i < 6; i++) d[5 - i] -= d[6 - i];
    for (int i = 1; i < 6; i++) d[i - 1] -= d[i];
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    FILE *f = fopen(argv[1], "r"); char line[4096];
    while (fgets(line, sizeof line, f) && nw < MAXW) {
        char *t = strtok(line, " \n"); strncpy(name[nw], t, 63);
        c34[nw] = strtoul(strtok(NULL, " \n"), NULL, 16);
        hex6(strtok(NULL, " \n"), ct[nw]);
        for (int k = 0; k < NWIN; k++) hex6(strtok(NULL, " \n"), win[nw][k]);
        nw++;
    }
    fclose(f);
    uint64_t lo = strtoull(argv[2], NULL, 16), hi = strtoull(argv[3], NULL, 16);
    uint8_t key[20], S[256];
    for (uint64_t m = lo; m < hi; m++) {
        uint32_t mask = (uint32_t)m;
        for (int i = 0; i < 5; i++) { uint32_t v = BASE[i] ^ mask; memcpy(key + 4 * i, &v, 4); }
        for (int i = 0; i < 256; i++) S[i] = (uint8_t)i;
        uint8_t j = 0;
        for (int i = 0; i < 256; i++) { j += S[i] + key[i % 20]; uint8_t t = S[i]; S[i] = S[j]; S[j] = t; }
        uint8_t ks[6]; uint8_t a = 0, b = 0;
        for (int x = 0; x < 6; x++) { a++; b += S[a]; uint8_t t = S[a]; S[a] = S[b]; S[b] = t; ks[x] = S[(uint8_t)(S[a] + S[b])]; }
        for (int w = 0; w < nw; w++) {
            uint8_t d[6]; memcpy(d, ct[w], 6); undiff(d);
            for (int x = 0; x < 6; x++) d[x] ^= ks[x];
            undiff(d);
            for (int k = 0; k < NWIN; k++)
                if (!memcmp(d, win[w][k], 6)) {
                    printf("%s mask=%08x c60=%08x off=+%d\n", name[w], mask, mask ^ c34[w] ^ 0xdf20ff20u, k);
                    fflush(stdout);
                }
        }
    }
    return 0;
}
