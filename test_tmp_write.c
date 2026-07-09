/*
 * Test program: writes to /tmp and exits.
 * A host/container-side smoke can verify whether DynamoRIO redirected the
 * write into /tmp/dr-sandbox/<session>/tmp instead of leaving a side effect at
 * the original /tmp path.
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define TMP_PATH "/tmp/shimmy-dr-tmp-side-effect.txt"

int main(void)
{
    const char *payload = "shimmy-dynamorio-private-tmp\n";
    int fd = open(TMP_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        printf("test_tmp_write: open(%s) failed errno=%d (%s)\n", TMP_PATH, errno, strerror(errno));
        return 1;
    }
    ssize_t n = write(fd, payload, strlen(payload));
    if (n != (ssize_t)strlen(payload)) {
        printf("test_tmp_write: write failed n=%zd errno=%d (%s)\n", n, errno, strerror(errno));
        close(fd);
        return 2;
    }
    if (close(fd) != 0) {
        printf("test_tmp_write: close failed errno=%d (%s)\n", errno, strerror(errno));
        return 3;
    }
    printf("test_tmp_write: wrote %s\n", TMP_PATH);
    return 0;
}
