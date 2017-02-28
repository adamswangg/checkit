/*
 * ---------------------------------------------------------------------------
 *  Copyright 2017 adams.wangg@gmail.com
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 * ---------------------------------------------------------------------------
*/

#include "checkit.h"

#define NULL 0

int SHA1_Init(SHA1_CTX *ctx)
{
    if (NULL == ctx) return 0;

    memset(ctx, 0, sizeof(SHA1_CTX));

    ctx->a = 0x67452301;
    ctx->b = 0xEFCDAB89;
    ctx->c = 0x98BADCFE;
    ctx->d = 0x10325476;
    ctx->e = 0xC3D2E1F0;

    return 1;
}

static int ltob(unsigned char *buffer, int len)
{
    unsigned char temp;
    int i;
    for (i = 0; i<len/2; i++) {
        temp = buffer[i];
        buffer[i] = buffer[len-i-1];
        buffer[len-i-1] = temp;
    }
    return 1;
}

static unsigned int swap_endianness(const unsigned int val)
{
    unsigned int res = 0;
    res |= (val & 0x000000ff) << 24;
    res |= (val & 0x0000ff00) << 8;
    res |= (val & 0x00ff0000) >> 8;
    res |= (val & 0xff000000) >> 24;
    return res;
}

static int _SHA1_Update(SHA1_CTX *ctx)
{
    unsigned int a = ctx->a;
    unsigned int b = ctx->b;
    unsigned int c = ctx->c;
    unsigned int d = ctx->d;
    unsigned int e = ctx->e;
    unsigned int w[80] = {0}, temp, i, f, k;

    memcpy(w, ctx->block, SHA1_BLOCK);
    for (i=0; i<16; i++) {
        w[i] = swap_endianness(w[i]);
    }

    // expand w array
    for (i=16; i<80; i++) {
        w[i] = LEFTROTATE(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1);
    }

    for (i=0; i<20; i++) {
        f = (b&c)|((~b)&d);
        k = 0x5a827999;
        ROUND(a, b, c, d, e, f, k, w[i], temp);
    }
    for (i=20; i<40; i++) {
        f = b^c^d;
        k = 0x6ed9eba1;
        ROUND(a, b, c, d, e, f, k, w[i], temp);
    }
    for (i=40; i<60; i++) {
        f = (b&c)|(b&d)|(c&d);
        k = 0x8f1bbcdc;
        ROUND(a, b, c, d, e, f, k, w[i], temp);
    }
    for (i=60; i<80; i++) {
        f = b^c^d;
        k = 0xca62c1d6;
        ROUND(a, b, c, d, e, f, k, w[i], temp);
    }

    ctx->a += a;
    ctx->b += b;
    ctx->c += c;
    ctx->d += d;
    ctx->e += e;

    return 1;
}

int SHA1_Update(SHA1_CTX *ctx, const unsigned char *data, unsigned long len)
{
    unsigned int copied=0, left=len, min;
    ctx->len += len*8;

    while (left > 0) {
        min = MIN(left, SHA1_BLOCK-ctx->block_len);
        memcpy(ctx->block+ctx->block_len, data+copied, min);
        ctx->block_len += min;
        copied += min;
        left -= min;
        if (ctx->block_len == SHA1_BLOCK) {
            _SHA1_Update(ctx);
            memset(ctx->block, 0, SHA1_BLOCK);
            ctx->block_len = 0;
        }
    }

    return 1;
}

unsigned char* SHA1_Final(unsigned char *md, SHA1_CTX *ctx)
{
    unsigned char mlen[8];
    int i;
    if (NULL == md) return NULL;

    ctx->block[ctx->block_len++] = 0x80;
    if (ctx->block_len <= 56) {

        memcpy(mlen, &(ctx->len), 8);
        ltob(mlen, 8);
        memcpy(ctx->block+56, mlen, 8);

        _SHA1_Update(ctx);
    } else {
        _SHA1_Update(ctx);

        memcpy(mlen, &(ctx->len), 8);
        ltob(mlen, 8);
        memcpy(ctx->block+56, mlen, 8);

        _SHA1_Update(ctx);
    }

    ctx->a = swap_endianness(ctx->a);
    ctx->b = swap_endianness(ctx->b);
    ctx->c = swap_endianness(ctx->c);
    ctx->d = swap_endianness(ctx->d);
    ctx->e = swap_endianness(ctx->e);
    memcpy(md, &(ctx->a), 4);
    memcpy(md+4, &(ctx->b), 4);
    memcpy(md+8, &(ctx->c), 4);
    memcpy(md+12, &(ctx->d), 4);
    memcpy(md+16, &(ctx->e), 4);

    return md;
}

