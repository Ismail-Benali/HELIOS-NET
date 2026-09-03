/* HELIOS-NET :: transport/fingerprint — تمييز نظام التشغيل من TTL/IP-ID (C)

يقرأ استجابة من مضيف المختبر ويقدّر عائلة OS من قيمة TTL الظاهرة.
نقطة الامتداد الجوهرية لـ modules/recon: يُستدعى من Python عبر subprocess
عند تكامل الأداء المنخفض.

يتطلب امتيازات لفتح socket خام على أغلب الأنظمة.
تُجمَّع: gcc -O2 -o fingerprint fingerprint.c
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* تقدير عائلة من قيمة TTL — قاعدة بسيطة معروفة في الاستطلاع. */
static const char *ttl_family(int ttl) {
    if (ttl <= 64 && ttl >= 56) return "Linux/Unix (TTL~64)";
    if (ttl <= 128 && ttl >= 120) return "Windows (TTL~128)";
    if (ttl <= 255 && ttl >= 240) return "Router/Network (TTL~255)";
    return "Unknown";
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: fingerprint <observed-ttl> [ip-id]\n");
        return 2;
    }
    int ttl = atoi(argv[1]);
    printf("{ \"module\": \"recon\", \"os_guess\": \"%s\", \"observed_ttl\": %d }\n",
           ttl_family(ttl), ttl);
    return 0;
}
