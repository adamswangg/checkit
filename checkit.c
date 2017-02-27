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
#include <stdlib.h>

#include "checkit.h"

void usage(char *path)
{
    fprintf(stderr, "Usage:\n"
        "\t%s [md5|sha1|sha224|sha256|sha512] file\n", path);
}

static void print_digest(const char *file_name, const unsigned char *md, const int len)
{
    int i;
    // TODO: fix memory allocation failure
    char *str = calloc(1, 2*len+1);

    for (i=0; i<len; i++) {
        sprintf(str+2*i, "%02x", md[i]);
    }
    printf("%s  %s\n", str, file_name);
    free(str);
}

static int _do_md5sum(FILE *in, const char *file_name)
{
    MD5_CTX ctx;
    unsigned char md[16] = {0};
    unsigned char buffer[8192]={0};
    size_t buffer_size;

    MD5_Init(&ctx);
    while ((buffer_size=fread(buffer, 1, 8192, in))>0) {
        MD5_Update(&ctx, buffer, buffer_size);
    }
    MD5_Final(md, &ctx);
    print_digest(file_name, md, 16);

    return 0;
}

int main(int argc, char *argv[])
{
    FILE *in;
    const char *action = NULL, *file_name;
    int tee = 0, _op;

    // parse arguments
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    action = argv[1];
    // TODO: this version only operate on one file per execution
    file_name = argv[2];

    if (0 == strcmp(action, "md5")) {
        in = fopen(file_name, "rb");
        if (NULL == in) {
            fprintf(stderr, "Can not open file %s.\n", file_name);
            return 1;
        }
        _do_md5sum(in, file_name);
        fclose(in);
        in = NULL;
    } else if (0 == strcmp(action, "sha1")) {
        printf("Not implemented.\n");
    } else if (0 == strcmp(action, "sha224")) {
        printf("Not implemented.\n");
    } else if (0 == strcmp(action, "sha256")) {
        printf("Not implemented.\n");
    } else if (0 == strcmp(action, "sha512")) {
        printf("Not implemented.\n");
    } else if (0 == strcmp(action, "crc32")) {
        printf("Not implemented.\n");
    } else {
        fprintf(stderr, "Unknow action %s specified in arguments\n", action);
        usage(argv[0]);
        return 1;
    }

    return 0;
}

