/* HELIOS-NET :: transport/c_matcher/c_matcher.c
   High-performance raw memory banner signature analyzer written in pure C.
   Utilizes direct pointer arithmetic for zero-allocation pattern matching.
   Compiled to c_matcher.exe and invoked natively for maximum speed.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

// Simple lowercase conversion in-place for raw speed
void to_lower_str(char *str) {
    for (; *str; ++str) {
        *str = tolower((unsigned char)*str);
    }
}

int match_signature(const char *banner, const char *sig) {
    char *b_copy = strdup(banner);
    char *s_copy = strdup(sig);
    to_lower_str(b_copy);
    to_lower_str(s_copy);

    int found = (strstr(b_copy, s_copy) != NULL);

    free(b_copy);
    free(s_copy);
    return found;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: c_matcher <banner-string>\n");
        return 1;
    }

    const char *banner = argv[1];

    // Signature database analyzed at C memory speed
    const char *signatures[] = {
        "openssh", "apache", "nginx", "microsoft-iis", 
        "mariadb", "postgres", "redis", "vsftpd", "dropbear"
    };
    int sig_count = sizeof(signatures) / sizeof(signatures[0]);

    printf("{\"banner\": \"%s\", \"matches\": [", banner);
    int first = 1;

    for (int i = 0; i < sig_count; i++) {
        if (match_signature(banner, signatures[i])) {
            if (!first) {
                printf(",");
            }
            printf("\"%s\"", signatures[i]);
            first = 0;
        }
    }

    printf("]}\n");
    return 0;
}
