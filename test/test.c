#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <string.h>
#include <sys/select.h>
#include <signal.h>
#include <stdlib.h>

static volatile int keep_running = 1;
static void on_sigint(int s){ (void)s; keep_running = 0; }

static int open_serial(const char *dev, speed_t baud)
{
    int fd = open(dev, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) { perror("open"); return -1; }

    struct termios tio;
    if (tcgetattr(fd, &tio) < 0) { perror("tcgetattr"); close(fd); return -1; }

    cfmakeraw(&tio);                  // raw mode (không xử lý ký tự)
    cfsetispeed(&tio, baud);
    cfsetospeed(&tio, baud);

    // 8N1, không flow control
    tio.c_cflag &= ~PARENB;           // no parity
    tio.c_cflag &= ~CSTOPB;           // 1 stop bit
    tio.c_cflag &= ~CSIZE;
    tio.c_cflag |= CS8;               // 8 data bits
    tio.c_cflag &= ~CRTSCTS;          // no HW flow control
    tio.c_cflag |= CLOCAL | CREAD;    // bật nhận

    // non-blocking read bằng select()
    tio.c_cc[VMIN]  = 0;
    tio.c_cc[VTIME] = 0;

    if (tcsetattr(fd, TCSANOW, &tio) < 0) { perror("tcsetattr"); close(fd); return -1; }
    tcflush(fd, TCIOFLUSH);           // xoá buffer cũ
    return fd;
}

int main(int argc, char **argv)
{
    const char *dev = (argc > 1) ? argv[1] : "/dev/serial0";
    // Nếu cần đổi baud, có thể thay B115200 ở đây
    int fd = open_serial(dev, B115200);
    if (fd < 0) return 1;

    signal(SIGINT, on_sigint);
    fprintf(stderr, "Listening on %s @115200 ... (Ctrl+C để thoát)\n", dev);

    unsigned char buf[512];
    char line[2048]; size_t lp = 0;

    while (keep_running) {
        fd_set rfds; FD_ZERO(&rfds); FD_SET(fd, &rfds);
        struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
        int rv = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (rv < 0) {
            if (errno == EINTR) continue;
            perror("select"); break;
        }
        if (rv == 0) continue; // timeout

        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            // Ghép theo dòng kết thúc bằng '\n'. Bỏ '\r' nếu có.
            for (ssize_t i = 0; i < n; ++i) {
                unsigned char c = buf[i];
                if (c == '\n' || lp >= sizeof(line)-1) {
                    line[lp] = '\0';
                    printf("%s\n", line);
                    fflush(stdout);
                    lp = 0;
                } else if (c != '\r') {
                    line[lp++] = (char)c;
                }
            }
        } else if (n < 0 && errno != EAGAIN) {
            perror("read"); break;
        }
    }

    // In nốt phần đệm nếu còn
    if (lp > 0) { line[lp] = '\0'; printf("%s\n", line); }

    close(fd);
    return 0;
}
