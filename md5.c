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

#include <stdio.h>
#include "checkit.h"

static const unsigned int S[64] =
{
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21 
};

static const unsigned int K[64] = 
{
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

int MD5_Init(MD5_CTX *ctx)
{
    if (NULL == ctx) {
        return 0;
    }

    memset(ctx, 0, sizeof(MD5_CTX));

    ctx->a = 0x67452301;
    ctx->b = 0xefcdab89;
    ctx->c = 0x98badcfe;
    ctx->d = 0x10325476;

    return 1;
}

static int _MD5_Update(MD5_CTX *ctx)
{
    unsigned int a = ctx->a;
    unsigned int b = ctx->b;
    unsigned int c = ctx->c;
    unsigned int d = ctx->d;
    unsigned int temp;
    unsigned int *chunk = (unsigned int *)ctx->block, index, f, g;

    // round 1
    for (index=0; index<16; index++) {
        f = (b&c)|(~b&d);
        g = index;

        temp = d;
        d = c;
        c = b;
        b = b + LEFTROTATE((a+f+K[index]+chunk[g]), S[index]);
        a = temp;
    }
    // round 2
    for (; index<32; index++) {
        f = (d&b)|(~d&c);
        g = (5*index+1)%16;

        temp = d;
        d = c;
        c = b;
        b = b + LEFTROTATE((a+f+K[index]+chunk[g]), S[index]);
        a = temp;
    }
    // round 3
    for (; index<48; index++) {
        f = b^c^d;
        g = (3*index+5)%16;

        temp = d;
        d = c;
        c = b;
        b = b + LEFTROTATE((a+f+K[index]+chunk[g]), S[index]);
        a = temp;
    }
    // round 4
    for (; index<64; index++) {
        f = c^(b|(~d));
        g = (7*index)%16;

        temp = d;
        d = c;
        c = b;
        b = b + LEFTROTATE((a+f+K[index]+chunk[g]), S[index]);
        a = temp;
    }
    ctx->a += a;
    ctx->b += b;
    ctx->c += c;
    ctx->d += d;
    
    return 1;
}

int MD5_Update(MD5_CTX *ctx, const unsigned char *data, unsigned long len)
{
    unsigned int copied=0, left=len, min;
    ctx->len += len*8; // count by bits

    while (left > 0) {
        min = MIN(left, MD5_BLOCK-ctx->block_len);
        memcpy(ctx->block+ctx->block_len, data+copied, min);
        ctx->block_len += min;
        copied += min;
        left -= min;
        if (ctx->block_len == MD5_BLOCK) {
            _MD5_Update(ctx);
            memset(ctx->block, 0, MD5_BLOCK);
            ctx->block_len = 0;
        }
    }

    return 1;
}

unsigned char* MD5_Final(unsigned char *md, MD5_CTX *ctx)
{
    int i;
    if (NULL == md) return NULL;

    ctx->block[ctx->block_len++] = 0x80;
    if (ctx->block_len <= 56) {
        memcpy(ctx->block+56, &(ctx->len), 8);
        _MD5_Update(ctx);
    } else {
        _MD5_Update(ctx);
        memcpy(ctx->block+56, &(ctx->len), 8);
        _MD5_Update(ctx);
    }

    memcpy(md, &(ctx->a), 4);
    memcpy(md+4, &(ctx->b), 4);
    memcpy(md+8, &(ctx->c), 4);
    memcpy(md+12, &(ctx->d), 4);

    return md;
}

