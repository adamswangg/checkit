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

#ifndef _SHA1_H
#define _SHA1_H

#define SHA1_BLOCK 64
#define ROUND(a, b, c, d, e, f, k, w, temp) \
    temp = LEFTROTATE(a, 5)+f+e+k+w; \
    e = d; \
    d = c; \
    c = LEFTROTATE(b, 30); \
    b = a; \
    a = temp;

typedef struct SHA1_CTX_ST
{
    unsigned int a, b, c, d, e;
    unsigned long long len;
    unsigned char block[SHA1_BLOCK];
    unsigned long block_len;
} SHA1_CTX;

int SHA1_Init(SHA1_CTX *ctx);
int SHA1_Update(SHA1_CTX *ctx, const unsigned char *data, unsigned long len);
unsigned char* SHA1_Final(unsigned char *md, SHA1_CTX *ctx);

#endif

