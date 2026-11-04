/**
 * Система:     ПО межсетевого экрана (ПО МЭ)
 * Подсистема:  ПС-1 Фильтрация
 * Модуль:      io
 * Назначение:  приём и отправка кадров L2-моста через AF_PACKET (Linux) или mock (macOS/тест)
 */
#define _POSIX_C_SOURCE 200809L
#include "io.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Linux-specific headers for AF_PACKET */
#ifdef __linux__
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#endif

#include "json_utils.h"

/* Структура интерфейса */
typedef struct {
    char    name[MAX_IFACE_NAME];
    int     rx_fd;              /* Дескриптор для приёма (-1 если не открыт) */
    int     tx_fd;              /* Дескриптор для отправки (-1 если не открыт) */
    int8_t  index;
    bool    enabled;
    bool    is_mgmt;            /* true = управляющий интерфейс */
    bool    is_mock;
} io_iface_t;

static io_iface_t s_ifaces[MAX_INTERFACES];
static uint8_t    s_iface_count = 0;
static bool       s_initialized = false;

/* ------------------------------------------------------------- */
/* Вспомогательные функции                                       */
/* ------------------------------------------------------------- */

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* ------------------------------------------------------------- */
/* Mock-бэкенд (macOS и тестирование)                            */
/* ------------------------------------------------------------- */

int io_init_mock(uint8_t iface_count) {
    if (s_initialized) io_cleanup();
    if (iface_count > MAX_INTERFACES) return -1;

    memset(s_ifaces, 0, sizeof(s_ifaces));
    for (int i = 0; i < MAX_INTERFACES; ++i) {
        s_ifaces[i].rx_fd = -1;
        s_ifaces[i].tx_fd = -1;
        s_ifaces[i].index = (int8_t)i;
    }

    for (uint8_t i = 0; i < iface_count; ++i) {
        int sv[2];
        /* Пара UNIX DGRAM-сокетов: sv[0] для inject/recv, sv[1] для send/drain */
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) {
            /* Откатить ранее созданные */
            for (uint8_t j = 0; j < i; ++j) {
                close(s_ifaces[j].rx_fd);
                close(s_ifaces[j].tx_fd);
            }
            return -1;
        }
        set_nonblocking(sv[0]);
        set_nonblocking(sv[1]);

        snprintf(s_ifaces[i].name, MAX_IFACE_NAME, "mock%u", i);
        s_ifaces[i].rx_fd   = sv[0];
        s_ifaces[i].tx_fd   = sv[1];
        s_ifaces[i].index   = (int8_t)i;
        s_ifaces[i].enabled = true;
        s_ifaces[i].is_mgmt = false;
        s_ifaces[i].is_mock = true;
    }

    s_iface_count = iface_count;
    s_initialized = true;
    return 0;
}

/* ------------------------------------------------------------- */
/* Linux AF_PACKET бэкенд                                        */
/* ------------------------------------------------------------- */

#ifdef __linux__
static int open_raw_socket(const char *ifname) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        fprintf(stderr, "io: socket(AF_PACKET) for %s failed: %s\n", ifname, strerror(errno));
        return -1;
    }

    /* Привязка к конкретному интерфейсу */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, "io: ioctl(SIOCGIFINDEX) for %s failed: %s\n", ifname, strerror(errno));
        close(fd);
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = ifr.ifr_ifindex;

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "io: bind(AF_PACKET) for %s failed: %s\n", ifname, strerror(errno));
        close(fd);
        return -1;
    }

    /* Promiscuous mode */
    struct packet_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = ifr.ifr_ifindex;
    mreq.mr_type    = PACKET_MR_PROMISC;
    setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    /* Игнорировать собственные исходящие пакеты */
    int ignore = 1;
    setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore, sizeof(ignore));

    set_nonblocking(fd);
    return fd;
}
#endif /* __linux__ */

/* ------------------------------------------------------------- */
/* Инициализация из config.json                                  */
/* ------------------------------------------------------------- */

int io_init(const char *config_path) {
    if (s_initialized) io_cleanup();

    const char *path = config_path;
    if (!path) path = "/etc/fw/config.json";

    /* Попытка открыть конфигурацию */
    FILE *f = fopen(path, "r");
    if (!f) {
        path = "/etc/default/config.json";
        f = fopen(path, "r");
    }
    if (!f) {
        /* Конфигурация не найдена: запускаемся без фильтрующих интерфейсов */
        fprintf(stderr, "io: no config found, starting with 0 filtering interfaces\n");
        memset(s_ifaces, 0, sizeof(s_ifaces));
        for (int i = 0; i < MAX_INTERFACES; ++i) {
            s_ifaces[i].rx_fd = -1;
            s_ifaces[i].tx_fd = -1;
            s_ifaces[i].index = (int8_t)i;
        }
        s_iface_count = 0;
        s_initialized = true;
        return 0;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 1024 * 1024) {
        fclose(f);
        memset(s_ifaces, 0, sizeof(s_ifaces));
        s_iface_count = 0;
        s_initialized = true;
        return 0;
    }

    char *json_str = (char *)malloc((size_t)fsize + 1);
    if (!json_str) { fclose(f); return -1; }

    size_t rd = fread(json_str, 1, (size_t)fsize, f);
    fclose(f);
    json_str[rd] = '\0';

    json_value_t *cfg = json_parse(json_str, NULL, 0);
    free(json_str);

    if (!cfg) {
        fprintf(stderr, "io: failed to parse %s, starting with 0 filtering interfaces\n", path);
        memset(s_ifaces, 0, sizeof(s_ifaces));
        s_iface_count = 0;
        s_initialized = true;
        return 0;
    }

    const json_value_t *ifaces_arr = json_obj_get(cfg, "ifaces");
    if (!ifaces_arr || ifaces_arr->type != JSON_TYPE_ARRAY || json_arr_len(ifaces_arr) == 0) {
        json_free(cfg);
        fprintf(stderr, "io: no ifaces in config, starting with 0 filtering interfaces\n");
        memset(s_ifaces, 0, sizeof(s_ifaces));
        s_iface_count = 0;
        s_initialized = true;
        return 0;
    }

    memset(s_ifaces, 0, sizeof(s_ifaces));
    for (int i = 0; i < MAX_INTERFACES; ++i) {
        s_ifaces[i].rx_fd = -1;
        s_ifaces[i].tx_fd = -1;
        s_ifaces[i].index = (int8_t)i;
    }
    uint8_t count = 0;

    for (size_t i = 0; i < json_arr_len(ifaces_arr) && count < MAX_INTERFACES; ++i) {
        const json_value_t *ifc = json_arr_get(ifaces_arr, i);
        if (!ifc) continue;

        const char *name = json_obj_get_str(ifc, "name", NULL);
        bool enabled = json_obj_get_bool(ifc, "enabled", true);
        bool is_mgmt = json_obj_get_bool(ifc, "is_mgmt", false);

        if (!name || !*name) continue;

        strncpy(s_ifaces[count].name, name, MAX_IFACE_NAME - 1);
        s_ifaces[count].index   = (int8_t)count;
        s_ifaces[count].enabled = enabled;
        s_ifaces[count].is_mgmt = is_mgmt;
        s_ifaces[count].is_mock = false;
        s_ifaces[count].rx_fd   = -1;
        s_ifaces[count].tx_fd   = -1;

        /* Управляющий интерфейс не участвует в фильтрации:
         * сокеты AF_PACKET для него НЕ открываются! */
        if (is_mgmt || !enabled) {
            count++;
            continue;
        }

#ifdef __linux__
        int fd = open_raw_socket(name);
        if (fd < 0) {
            fprintf(stderr, "io: skipping interface %s (failed to open)\n", name);
            count++;
            continue;
        }
        s_ifaces[count].rx_fd = fd;
        s_ifaces[count].tx_fd = fd; /* Один дескриптор для RX и TX */
#else
        /* macOS: подставляем mock вместо AF_PACKET */
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0) {
            set_nonblocking(sv[0]);
            set_nonblocking(sv[1]);
            s_ifaces[count].rx_fd   = sv[0];
            s_ifaces[count].tx_fd   = sv[1];
            s_ifaces[count].is_mock = true;
        }
#endif
        count++;
    }

    json_free(cfg);

    s_iface_count = count;
    s_initialized = true;
    return 0;
}

/* ------------------------------------------------------------- */
/* Cleanup                                                       */
/* ------------------------------------------------------------- */

void io_cleanup(void) {
    for (uint8_t i = 0; i < MAX_INTERFACES; ++i) {
        if (s_ifaces[i].rx_fd >= 0) {
            close(s_ifaces[i].rx_fd);
        }
        if (s_ifaces[i].tx_fd >= 0 && s_ifaces[i].tx_fd != s_ifaces[i].rx_fd) {
            close(s_ifaces[i].tx_fd);
        }
        s_ifaces[i].rx_fd = -1;
        s_ifaces[i].tx_fd = -1;
    }
    memset(s_ifaces, 0, sizeof(s_ifaces));
    s_iface_count = 0;
    s_initialized = false;
}

/* ------------------------------------------------------------- */
/* Приём и отправка                                              */
/* ------------------------------------------------------------- */

int io_recv_frame(int iface_idx, uint8_t *buf, size_t max_len, size_t *out_len) {
    if (iface_idx < 0 || iface_idx >= (int)s_iface_count) return -1;
    if (s_ifaces[iface_idx].is_mgmt) return -1;
    if (!buf || max_len == 0 || !out_len) return -1;

    int fd = s_ifaces[iface_idx].rx_fd;
    if (fd < 0) return -1;

    ssize_t r = recv(fd, buf, max_len, 0);
    if (r <= 0) return -1;

    *out_len = (size_t)r;
    return 0;
}

int io_send_frame(int iface_idx, const uint8_t *buf, size_t len) {
    if (iface_idx < 0 || iface_idx >= (int)s_iface_count) return -1;
    if (s_ifaces[iface_idx].is_mgmt) return -1;
    if (!buf || len == 0) return -1;

    int fd = s_ifaces[iface_idx].tx_fd;
    if (fd < 0) return -1;

#ifdef __linux__
    if (!s_ifaces[iface_idx].is_mock) {
        /* На Linux отправляем через sendto с привязкой к интерфейсу */
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family   = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, s_ifaces[iface_idx].name, IFNAMSIZ - 1);
        if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) return -1;
        sll.sll_ifindex = ifr.ifr_ifindex;
        sll.sll_halen   = 6;

        /* MAC назначения из первых 6 байт кадра */
        if (len >= 6) memcpy(sll.sll_addr, buf, 6);

        ssize_t w = sendto(fd, buf, len, 0, (struct sockaddr *)&sll, sizeof(sll));
        return (w == (ssize_t)len) ? 0 : -1;
    }
#endif

    /* Mock или macOS fallback */
    ssize_t w = send(fd, buf, len, 0);
    return (w == (ssize_t)len) ? 0 : -1;
}

int io_get_fd(int iface_idx) {
    if (iface_idx < 0 || iface_idx >= (int)s_iface_count) return -1;
    if (s_ifaces[iface_idx].is_mgmt) return -1;
    return s_ifaces[iface_idx].rx_fd;
}

uint8_t io_get_iface_count(void) {
    return s_iface_count;
}

bool io_is_mgmt_iface(int8_t iface_idx) {
    if (iface_idx < 0 || iface_idx >= MAX_INTERFACES) return false;
    return s_ifaces[iface_idx].is_mgmt;
}

bool io_is_mgmt_iface_name(const char *name) {
    if (!name || !*name) return false;
    for (uint8_t i = 0; i < s_iface_count; ++i) {
        if (strncmp(s_ifaces[i].name, name, MAX_IFACE_NAME) == 0) {
            return s_ifaces[i].is_mgmt;
        }
    }
    return false;
}

int8_t io_get_iface_index_by_name(const char *name) {
    if (!name || !*name) return -1;
    for (uint8_t i = 0; i < s_iface_count; ++i) {
        if (strncmp(s_ifaces[i].name, name, MAX_IFACE_NAME) == 0) {
            return s_ifaces[i].index;
        }
    }
    return -1;
}

const char *io_get_iface_name(int8_t iface_idx) {
    if (iface_idx < 0 || iface_idx >= s_iface_count) return NULL;
    return s_ifaces[iface_idx].name;
}

int io_set_iface_mgmt(int8_t iface_idx, bool is_mgmt) {
    if (iface_idx < 0 || iface_idx >= MAX_INTERFACES) return -1;
    if (iface_idx >= s_iface_count) {
        for (uint8_t j = s_iface_count; j <= (uint8_t)iface_idx; ++j) {
            s_ifaces[j].rx_fd = -1;
            s_ifaces[j].tx_fd = -1;
            s_ifaces[j].index = (int8_t)j;
        }
        s_iface_count = (uint8_t)(iface_idx + 1);
    }
    s_ifaces[iface_idx].is_mgmt = is_mgmt;
    if (is_mgmt && s_initialized) {
        if (s_ifaces[iface_idx].rx_fd >= 0) {
            close(s_ifaces[iface_idx].rx_fd);
            s_ifaces[iface_idx].rx_fd = -1;
        }
        if (s_ifaces[iface_idx].tx_fd >= 0 && s_ifaces[iface_idx].tx_fd != s_ifaces[iface_idx].rx_fd) {
            close(s_ifaces[iface_idx].tx_fd);
            s_ifaces[iface_idx].tx_fd = -1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------- */
/* Тестовые хелперы (mock)                                       */
/* ------------------------------------------------------------- */

int io_inject_frame(int iface_idx, const uint8_t *buf, size_t len) {
    if (iface_idx < 0 || iface_idx >= (int)s_iface_count) return -1;
    if (s_ifaces[iface_idx].is_mgmt) return -1;
    if (!s_ifaces[iface_idx].is_mock) return -1;
    if (!buf || len == 0) return -1;

    /* Записать в tx_fd -> читается из rx_fd (socketpair) */
    ssize_t w = send(s_ifaces[iface_idx].tx_fd, buf, len, 0);
    return (w == (ssize_t)len) ? 0 : -1;
}

int io_drain_frame(int iface_idx, uint8_t *buf, size_t max_len, size_t *out_len) {
    if (iface_idx < 0 || iface_idx >= (int)s_iface_count) return -1;
    if (s_ifaces[iface_idx].is_mgmt) return -1;
    if (!s_ifaces[iface_idx].is_mock) return -1;
    if (!buf || max_len == 0 || !out_len) return -1;

    /* Читать из rx_fd то, что io_send_frame записал в tx_fd.
     * Но socketpair DGRAM симметричен: send на tx_fd -> recv на rx_fd.
     * io_send_frame отправляет на tx_fd, значит читать нужно из rx_fd. */
    ssize_t r = recv(s_ifaces[iface_idx].rx_fd, buf, max_len, 0);
    if (r <= 0) return -1;
    *out_len = (size_t)r;
    return 0;
}
