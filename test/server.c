// // server.c
// #define _GNU_SOURCE
// #include <stdio.h>
// #include <stdlib.h>
// #include <stdint.h>
// #include <string.h>
// #include <pthread.h>
// #include <time.h>
// #include <errno.h>
// #include <unistd.h>
// #include <ctype.h>

// #include "civetweb.h"        // thêm civetweb.c/.h vào project
// #include "crypto_aead.h"
// #include "api.h"

// // ====== cấu hình ======
// static const char *LISTEN_ADDR = "0.0.0.0:8080";
// static const char *DOCROOT     = ".";   // chứa login.html, index.html, change_password.html
// static const char *SERIAL_DEV  = "/dev/serial0"; // test1 sẽ dùng dev này

// // ====== NEW_KEY/NEW_AD PHẢI TRÙNG VỚI test1.c khi mã hóa lần 2 ======
// static const uint8_t NEW_KEY[CRYPTO_KEYBYTES] = {
//   0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
//   0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
// };
// static const uint8_t NEW_AD[16] = {
//   0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
//   0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F
// };

// // ====== dữ liệu chia sẻ cho web ======
// typedef struct {
//   int has_data;
//   uint8_t light, motion, temp, hum;
//   uint8_t lat_deg, lat_min, lat_sec; char lat_hem;
//   uint8_t lon_deg, lon_min, lon_sec; char lon_hem;
//   double ts;
// } latest_t;

// static latest_t g_latest = {0};
// static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

// // ====== AUTH (đơn giản) ======
// static const char *OK_USER = "admin";
// static char g_password[64] = "admin";  // mật khẩu hiện tại (demo); có thể nạp từ file/env
// static pthread_mutex_t g_pwd_lock = PTHREAD_MUTEX_INITIALIZER;

// // token phiên đăng nhập (đơn giản, đủ dùng LAN)
// static char SESSION_TOKEN[33] = {0};

// static void gen_token(void){
//   for (int i = 0; i < 32; i++) {
//     int v = rand() % 16;
//     SESSION_TOKEN[i] = "0123456789abcdef"[v];
//   }
//   SESSION_TOKEN[32] = 0;
// }

// static int is_logged_in(struct mg_connection *c){
//   const char *cookie = mg_get_header(c, "Cookie");
//   if (!cookie) return 0;
//   const char *sid = strstr(cookie, "sid=");
//   if (!sid) return 0;
//   sid += 4; // skip "sid="
//   // so sánh token hiện tại xuất hiện trong cookie
//   return (strstr(sid, SESSION_TOKEN) != NULL);
// }

// // ====== tiện ích ======
// static int hex2bytes(const char *hx, uint8_t *out, size_t cap, size_t *olen){
//   size_t L = strlen(hx);
//   if (L % 2) return 0;
//   size_t n = L/2;
//   if (n > cap) return 0;
//   for (size_t i=0;i<n;i++){
//     unsigned v;
//     if (sscanf(&hx[2*i], "%2x", &v) != 1) return 0;
//     out[i] = (uint8_t)v;
//   }
//   if (olen) *olen = n;
//   return 1;
// }

// // đọc toàn bộ body nhỏ (JSON) vào buffer
// static int read_body(struct mg_connection *c, char *buf, size_t cap){
//   int n = mg_read(c, buf, (int)cap - 1);
//   if (n < 0) n = 0;
//   buf[n] = '\0';
//   return n;
// }

// // trim spaces
// static const char* skip_ws(const char *p){ while (p && *p && isspace((unsigned char)*p)) p++; return p; }

// // lấy chuỗi JSON rất đơn giản: {"key":"value"} -> value (không escape phức tạp)
// static int json_get_string(const char *body, const char *key, char *out, size_t outcap){
//   if (!body || !key || !out || outcap==0) return 0;
//   // tìm "key"
//   char pat[128];
//   snprintf(pat, sizeof(pat), "\"%s\"", key);
//   const char *p = strstr(body, pat);
//   if (!p) return 0;
//   p += strlen(pat);
//   p = skip_ws(p);
//   if (*p != ':') return 0;
//   p++;
//   p = skip_ws(p);
//   if (*p != '\"') return 0;
//   p++; // vào trong chuỗi
//   size_t k = 0;
//   while (*p && *p != '\"' && k+1 < outcap) {
//     if (*p == '\\' && p[1]) { // copy char sau backslash
//       p++; out[k++] = *p++;
//     } else {
//       out[k++] = *p++;
//     }
//   }
//   if (*p != '\"') return 0;
//   out[k] = '\0';
//   return 1;
// }

// // ====== đọc stdout của test1, gom 3 dòng, giải mã bằng NEW_KEY ======
// static void *reader_thread(void *arg){
//   (void)arg;
//   char cmd[256];
//   snprintf(cmd, sizeof(cmd), "./test1 %s", SERIAL_DEV);
//   FILE *fp = popen(cmd, "r");
//   if (!fp){ perror("popen test1"); return NULL; }

//   char line[65536];
//   char hx_nonce[256], hx_ct[65536], hx_tag[256];
//   int have = 0;

//   while (fgets(line, sizeof(line), fp)) {
//     // bỏ \r\n
//     line[strcspn(line, "\r\n")] = 0;
//     if (line[0] == 0) continue;

//     if (have == 0) { strncpy(hx_nonce, line, sizeof(hx_nonce)-1); hx_nonce[sizeof(hx_nonce)-1]=0; have=1; continue; }
//     if (have == 1) { strncpy(hx_ct,    line, sizeof(hx_ct)-1);    hx_ct[sizeof(hx_ct)-1]=0;    have=2; continue; }
//     if (have == 2) { strncpy(hx_tag,   line, sizeof(hx_tag)-1);   hx_tag[sizeof(hx_tag)-1]=0;  have=3; }

//     if (have == 3) {
//       // chuyển hex -> bytes
//       uint8_t npub[CRYPTO_NPUBBYTES], tag[CRYPTO_ABYTES];
//       size_t nlen=0,tlen=0,clen=0;
//       if (!hex2bytes(hx_nonce, npub, sizeof(npub), &nlen) || nlen != CRYPTO_NPUBBYTES) { have=0; continue; }
//       if (!hex2bytes(hx_tag,   tag,  sizeof(tag),  &tlen) || tlen != CRYPTO_ABYTES)     { have=0; continue; }

//       size_t hexlen = strlen(hx_ct);
//       if (hexlen % 2) { have=0; continue; }
//       clen = hexlen/2;
//       uint8_t *ct_tag = (uint8_t*)malloc(clen + CRYPTO_ABYTES);
//       if (!ct_tag) { have=0; continue; }
//       size_t clen2=0;
//       if (!hex2bytes(hx_ct, ct_tag, clen, &clen2) || clen2 != clen) { free(ct_tag); have=0; continue; }
//       memcpy(ct_tag + clen, tag, tlen);

//       // Giải mã (NEW_KEY/NEW_AD)
//       uint8_t pt[65536]; unsigned long long ptlen=0;
//       int rc = crypto_aead_decrypt(pt, &ptlen, NULL,
//                                    ct_tag, (unsigned long long)(clen + tlen),
//                                    NEW_AD, sizeof(NEW_AD),
//                                    npub, NEW_KEY);
//       free(ct_tag);

//       if (rc == 0 && ptlen == 12){
//         pthread_mutex_lock(&g_lock);
//         g_latest.has_data = 1;
//         g_latest.light  = pt[0];
//         g_latest.motion = pt[1];
//         g_latest.temp   = pt[2];
//         g_latest.hum    = pt[3];
//         g_latest.lat_deg = pt[4]; g_latest.lat_min = pt[5]; g_latest.lat_sec = pt[6];
//         g_latest.lat_hem = (pt[7] >= 32 && pt[7] <= 126) ? (char)pt[7] : '?';
//         g_latest.lon_deg = pt[8]; g_latest.lon_min = pt[9]; g_latest.lon_sec = pt[10];
//         g_latest.lon_hem = (pt[11]>= 32 && pt[11]<= 126) ? (char)pt[11] : '?';
//         g_latest.ts = (double)time(NULL);
//         pthread_mutex_unlock(&g_lock);
//       }
//       have = 0; // nhận packet kế tiếp
//     }
//   }

//   pclose(fp);
//   return NULL;
// }

// // ====== HTTP handlers ======

// // YÊU CẦU ĐĂNG NHẬP để đọc dữ liệu (bỏ check nếu không cần)
// // static int h_api_latest(struct mg_connection *c, void *cb){
// //   (void)cb;

// //   if (!is_logged_in(c)) {
// //     mg_printf(c, "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{\"ok\":false,\"error\":\"unauthorized\"}");
// //     return 401;
// //   }

// //   pthread_mutex_lock(&g_lock);
// //   latest_t L = g_latest;
// //   pthread_mutex_unlock(&g_lock);

// //   mg_printf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n");
// //   if (!L.has_data){ mg_printf(c, "{\"ok\":true,\"data\":null}"); return 200; }
// //   char latbuf[64], lonbuf[64];
// //   snprintf(latbuf, sizeof(latbuf), "%u° %u' %u\" %c", L.lat_deg, L.lat_min, L.lat_sec, L.lat_hem?L.lat_hem:'?');
// //   snprintf(lonbuf, sizeof(lonbuf), "%u° %u' %u\" %c", L.lon_deg, L.lon_min, L.lon_sec, L.lon_hem?L.lon_hem:'?');

// //   mg_printf(c,
// //     "{\"ok\":true,\"data\":{"
// //       "\"ts\":%.0f,"
// //       "\"parsed\":{"
// //         "\"light\":%u,\"motion\":%u,"
// //         "\"temperature\":%u,\"humidity\":%u,"
// //         "\"latitude\":\"%s\",\"longitude\":\"%s\""
// //       "}"
// //     "}}",
// //     L.ts, L.light, L.motion, L.temp, L.hum, latbuf, lonbuf
// //   );
// //   return 200;
// // }
// static int h_api_latest(struct mg_connection *c, void *cb){
//   (void)cb;

//   pthread_mutex_lock(&g_lock);
//   latest_t L = g_latest;
//   pthread_mutex_unlock(&g_lock);

//   mg_printf(c,
//     "HTTP/1.1 200 OK\r\n"
//     "Content-Type: application/json\r\n"
//     "Cache-Control: no-store\r\n"
//     "Access-Control-Allow-Origin: *\r\n"
//     "Access-Control-Allow-Credentials: false\r\n"
//     "\r\n");

//   if (!L.has_data) {
//     mg_printf(c, "{\"ok\":true,\"data\":null}");
//     return 200;
//   }

//   mg_printf(c,
//     "{"
//       "\"ok\":true,"
//       "\"data\":{"
//         "\"ts\":%.0f,"
//         "\"parsed\":{"
//           "\"light\":%u,"
//           "\"motion\":%u,"
//           "\"temperature\":%u,"
//           "\"humidity\":%u,"
//           "\"latitude\":{\"deg\":%u,\"min\":%u,\"sec\":%u,\"dir\":\"%c\"},"
//           "\"longitude\":{\"deg\":%u,\"min\":%u,\"sec\":%u,\"dir\":\"%c\"}"
//         "}"
//       "}"
//     "}",
//     L.ts, L.light, L.motion, L.temp, L.hum,
//     L.lat_deg, L.lat_min, L.lat_sec, L.lat_hem ? L.lat_hem : '?',
//     L.lon_deg, L.lon_min, L.lon_sec, L.lon_hem ? L.lon_hem : '?'
//   );
//   return 200;
// }


// // POST /api/login  body: {"username":"...","password":"..."}
// static int h_api_login(struct mg_connection *c, void *cb) {
//   (void)cb;
//   char body[1024];
//   read_body(c, body, sizeof(body));

//   char username[128] = {0}, password[128] = {0};

//   json_get_string(body, "username", username, sizeof(username));
//   json_get_string(body, "password", password, sizeof(password));

//   int ok = 0;
//   if (strcmp(username, OK_USER) == 0) {
//     pthread_mutex_lock(&g_pwd_lock);
//     ok = (strcmp(password, g_password) == 0);
//     pthread_mutex_unlock(&g_pwd_lock);
//   }

//   if (ok) {
//     gen_token();
//     mg_printf(c,
//       "HTTP/1.1 200 OK\r\n"
//       "Content-Type: application/json\r\n"
//       "Set-Cookie: sid=%s; HttpOnly; Path=/\r\n"
//       "\r\n"
//       "{\"ok\":true}", SESSION_TOKEN);
//   } else {
//     mg_printf(c,
//       "HTTP/1.1 401 Unauthorized\r\n"
//       "Content-Type: application/json\r\n"
//       "\r\n"
//       "{\"ok\":false,\"error\":\"bad_credentials\"}");
//   }
//   return 200;
// }

// // POST /api/logout  (xóa cookie)
// static int h_api_logout(struct mg_connection *c, void *cb) {
//   (void)cb;
//   mg_printf(c,
//     "HTTP/1.1 200 OK\r\n"
//     "Content-Type: application/json\r\n"
//     "Set-Cookie: sid=; Max-Age=0; Path=/\r\n"
//     "\r\n"
//     "{\"ok\":true}");
//   return 200;
// }

// // POST /api/change_password  body: {"old_password":"...","new_password":"..."}
// static int h_api_change_password(struct mg_connection *c, void *cb) {
//   (void)cb;

//   if (!is_logged_in(c)) {
//     mg_printf(c, "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{\"ok\":false,\"error\":\"unauthorized\"}");
//     return 401;
//   }

//   char body[1024];
//   read_body(c, body, sizeof(body));

//   char oldp[128] = {0}, newp[128] = {0};
//   json_get_string(body, "old_password", oldp, sizeof(oldp));
//   json_get_string(body, "new_password", newp, sizeof(newp));

//   int ok_old = 0;
//   pthread_mutex_lock(&g_pwd_lock);
//   ok_old = (strcmp(oldp, g_password) == 0);
//   if (!ok_old) {
//     pthread_mutex_unlock(&g_pwd_lock);
//     mg_printf(c, "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"ok\":false,\"error\":\"wrong_old_password\"}");
//     return 200;
//   }

//   if (strlen(newp) < 6) {
//     pthread_mutex_unlock(&g_pwd_lock);
//     mg_printf(c, "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"ok\":false,\"error\":\"weak_password\"}");
//     return 200;
//   }

//   // đặt mật khẩu mới
//   strncpy(g_password, newp, sizeof(g_password)-1);
//   g_password[sizeof(g_password)-1] = 0;
//   pthread_mutex_unlock(&g_pwd_lock);

//   mg_printf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}");
//   return 200;
// }

// // fallback: phục vụ static (index.html, login.html, change_password.html)
// static int h_static(struct mg_connection *c, void *cb){ (void)c;(void)cb; return 0; }

// int main(int argc, char **argv){
//   if (argc > 1) SERIAL_DEV = argv[1]; // cho phép đổi serial dev khi chạy
//   srand((unsigned)time(NULL));

//   // 1) start reader thread (spawn test1)
//   pthread_t th;
//   if (pthread_create(&th, NULL, reader_thread, NULL) != 0) {
//     perror("pthread_create"); return 1;
//   }

//   // 2) start HTTP server
//   const char *options[] = {
//     "document_root", DOCROOT,
//     "listening_ports", LISTEN_ADDR,
//     "enable_directory_listing", "no",
//     0
//   };
//   struct mg_callbacks cb; memset(&cb,0,sizeof(cb));
//   struct mg_context *ctx = mg_start(&cb, NULL, options);
//   if (!ctx){ fprintf(stderr,"HTTP start failed\n"); return 1; }

//   // API routes
//   mg_set_request_handler(ctx, "/api/login",           h_api_login, 0);
//   mg_set_request_handler(ctx, "/api/logout",          h_api_logout, 0);
//   mg_set_request_handler(ctx, "/api/change_password", h_api_change_password, 0);
//   mg_set_request_handler(ctx, "/api/latest",          h_api_latest, 0);

//   // static
//   mg_set_request_handler(ctx, "/", h_static, 0);

//   fprintf(stderr,"Dashboard at http://%s (docroot=%s)\n", LISTEN_ADDR, DOCROOT);
//   fprintf(stderr,"Spawning: ./test1 %s\n", SERIAL_DEV);

//   // 3) loop forever
//   // while (1) mg_sleep(1000);
//   while (1) { usleep(1000 * 1000); }
//   // (không tới đây)
//   mg_stop(ctx);
//   return 0;
// }

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <termios.h>

#include "civetweb.h"
#include "crypto_aead.h"
#include "api.h"

// ====== cấu hình ======
static const char *LISTEN_ADDR = "0.0.0.0:8080";
static const char *DOCROOT     = ".";   // chứa login.html, index.html, change_password.html
static const char *SERIAL_DEV  = "/dev/serial0"; // test1 sẽ dùng dev này

// ====== NEW_KEY/NEW_AD PHẢI TRÙNG VỚI test1.c khi mã hóa lần 2 ======
static const uint8_t NEW_KEY[CRYPTO_KEYBYTES] = {
  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
  0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
};
static const uint8_t NEW_AD[16] = {
  0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
  0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F
};

// ====== dữ liệu chia sẻ cho web ======
typedef struct {
  int has_data;
  uint8_t light, motion, temp, hum;
  uint8_t lat_deg, lat_min, lat_sec; char lat_hem;
  uint8_t lon_deg, lon_min, lon_sec; char lon_hem;
  double ts;
} latest_t;

static latest_t g_latest = {0};
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

// ====== AUTH (đơn giản) ======
static const char *OK_USER = "admin";
static char g_password[64] = "admin";  // mật khẩu hiện tại (demo); có thể nạp từ file/env
static pthread_mutex_t g_pwd_lock = PTHREAD_MUTEX_INITIALIZER;

// token phiên đăng nhập (đơn giản, đủ dùng LAN)
static char SESSION_TOKEN[33] = {0};

static void gen_token(void) {
  for (int i = 0; i < 32; i++) {
    int v = rand() % 16;
    SESSION_TOKEN[i] = "0123456789abcdef"[v];
  }
  SESSION_TOKEN[32] = 0;
}

static int is_logged_in(struct mg_connection *c) {
  const char *cookie = mg_get_header(c, "Cookie");
  if (!cookie) return 0;
  const char *sid = strstr(cookie, "sid=");
  if (!sid) return 0;
  sid += 4; // skip "sid="
  return (strstr(sid, SESSION_TOKEN) != NULL);
}

// ====== tiện ích ======
static int hex2bytes(const char *hx, uint8_t *out, size_t cap, size_t *olen) {
  size_t L = strlen(hx);
  if (L % 2) return 0;
  size_t n = L/2;
  if (n > cap) return 0;
  for (size_t i = 0; i < n; i++) {
    unsigned v;
    if (sscanf(&hx[2*i], "%2x", &v) != 1) return 0;
    out[i] = (uint8_t)v;
  }
  if (olen) *olen = n;
  return 1;
}

static int read_body(struct mg_connection *c, char *buf, size_t cap) {
  int n = mg_read(c, buf, (int)cap - 1);
  if (n < 0) n = 0;
  buf[n] = '\0';
  return n;
}

static const char* skip_ws(const char *p) { 
  while (p && *p && isspace((unsigned char)*p)) p++; 
  return p; 
}

static int json_get_string(const char *body, const char *key, char *out, size_t outcap) {
  if (!body || !key || !out || outcap == 0) return 0;
  char pat[128];
  snprintf(pat, sizeof(pat), "\"%s\"", key);
  const char *p = strstr(body, pat);
  if (!p) return 0;
  p += strlen(pat);
  p = skip_ws(p);
  if (*p != ':') return 0;
  p++;
  p = skip_ws(p);
  if (*p != '\"') return 0;
  p++;
  size_t k = 0;
  while (*p && *p != '\"' && k+1 < outcap) {
    if (*p == '\\' && p[1]) {
      p++; out[k++] = *p++;
    } else {
      out[k++] = *p++;
    }
  }
  if (*p != '\"') return 0;
  out[k] = '\0';
  return 1;
}

// ====== WebSocket handlers ======
static int websocket_connect_handler(const struct mg_connection *conn, void *cbdata) {
  (void)cbdata;
  printf("WebSocket kết nối\n");
  return 0; // Chấp nhận kết nối
}

static void websocket_ready_handler(struct mg_connection *conn, void *cbdata) {
  (void)cbdata;
  printf("WebSocket sẵn sàng\n");
  // Gửi dữ liệu hiện tại khi client sẵn sàng
  pthread_mutex_lock(&g_lock);
  latest_t L = g_latest;
  pthread_mutex_unlock(&g_lock);
  if (L.has_data) {
    char response[512];
    snprintf(response, sizeof(response),
             "{\"ok\":true,\"data\":{\"parsed\":{"
             "\"light\":%u,\"motion\":%u,\"temperature\":%u,\"humidity\":%u,"
             "\"latitude\":{\"deg\":%u,\"min\":%u,\"sec\":%u,\"dir\":\"%c\"},"
             "\"longitude\":{\"deg\":%u,\"min\":%u,\"sec\":%u,\"dir\":\"%c\"}"
             "},\"ts\":%.0f}}",
             L.light, L.motion, L.temp, L.hum,
             L.lat_deg, L.lat_min, L.lat_sec, L.lat_hem ? L.lat_hem : '?',
             L.lon_deg, L.lon_min, L.lon_sec, L.lon_hem ? L.lon_hem : '?',
             L.ts);
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, response, strlen(response));
  }
}

static int websocket_data_handler(struct mg_connection *conn, int opcode, char *data, size_t datasize, void *cbdata) {
  (void)conn; (void)opcode; (void)data; (void)datasize; (void)cbdata;
  // Có thể xử lý tin nhắn từ client nếu cần
  return 1; // Tiếp tục kết nối
}

static void websocket_close_handler(const struct mg_connection *conn, void *cbdata) {
  (void)conn; (void)cbdata;
  printf("WebSocket ngắt kết nối\n");
}

// ====== đọc stdout của test1, gom 3 dòng, giải mã bằng NEW_KEY ======
static void *reader_thread(void *arg) {
  struct mg_context *ctx = (struct mg_context*)arg;
  clock_t start = clock();
  char cmd[256];
  snprintf(cmd, sizeof(cmd), "./test1 %s", SERIAL_DEV);
  printf("Đang chạy: %s\n", cmd);
  FILE *fp = popen(cmd, "r");
  if (!fp) {
    fprintf(stderr, "Lỗi popen test1: %s\n", strerror(errno));
    return NULL;
  }
  printf("Khởi tạo test1 mất %f giây\n", (double)(clock() - start) / CLOCKS_PER_SEC);

  char line[65536];
  char hx_nonce[256], hx_ct[65536], hx_tag[256];
  int have = 0;

  while (fgets(line, sizeof(line), fp)) {
    start = clock();
    line[strcspn(line, "\r\n")] = 0;
    if (line[0] == 0) continue;

    if (have == 0) { strncpy(hx_nonce, line, sizeof(hx_nonce)-1); hx_nonce[sizeof(hx_nonce)-1]=0; have=1; continue; }
    if (have == 1) { strncpy(hx_ct,    line, sizeof(hx_ct)-1);    hx_ct[sizeof(hx_ct)-1]=0;    have=2; continue; }
    if (have == 2) { strncpy(hx_tag,   line, sizeof(hx_tag)-1);   hx_tag[sizeof(hx_tag)-1]=0;  have=3; }

    if (have == 3) {
      uint8_t npub[CRYPTO_NPUBBYTES], tag[CRYPTO_ABYTES];
      size_t nlen=0, tlen=0, clen=0;
      if (!hex2bytes(hx_nonce, npub, sizeof(npub), &nlen) || nlen != CRYPTO_NPUBBYTES) { have=0; continue; }
      if (!hex2bytes(hx_tag,   tag,  sizeof(tag),  &tlen) || tlen != CRYPTO_ABYTES)     { have=0; continue; }

      size_t hexlen = strlen(hx_ct);
      if (hexlen % 2) { have=0; continue; }
      clen = hexlen/2;
      uint8_t *ct_tag = (uint8_t*)malloc(clen + CRYPTO_ABYTES);
      if (!ct_tag) { have=0; continue; }
      size_t clen2=0;
      if (!hex2bytes(hx_ct, ct_tag, clen, &clen2) || clen2 != clen) { free(ct_tag); have=0; continue; }
      memcpy(ct_tag + clen, tag, tlen);

      uint8_t pt[65536]; unsigned long long ptlen=0;
      int rc = crypto_aead_decrypt(pt, &ptlen, NULL,
                                   ct_tag, (unsigned long long)(clen + tlen),
                                   NEW_AD, sizeof(NEW_AD),
                                   npub, NEW_KEY);
      free(ct_tag);

      if (rc == 0 && ptlen == 12) {
        pthread_mutex_lock(&g_lock);
        g_latest.has_data = 1;
        g_latest.light  = pt[0];
        g_latest.motion = pt[1];
        g_latest.temp   = pt[2];
        g_latest.hum    = pt[3];
        g_latest.lat_deg = pt[4]; g_latest.lat_min = pt[5]; g_latest.lat_sec = pt[6];
        g_latest.lat_hem = (pt[7] >= 32 && pt[7] <= 126) ? (char)pt[7] : '?';
        g_latest.lon_deg = pt[8]; g_latest.lon_min = pt[9]; g_latest.lon_sec = pt[10];
        g_latest.lon_hem = (pt[11]>= 32 && pt[11]<= 126) ? (char)pt[11] : '?';
        g_latest.ts = (double)time(NULL);
        // Gửi qua WebSocket
        if (ctx) {
          char response[512];
          snprintf(response, sizeof(response),
                   "{\"ok\":true,\"data\":{\"parsed\":{"
                   "\"light\":%u,\"motion\":%u,\"temperature\":%u,\"humidity\":%u,"
                   "\"latitude\":{\"deg\":%u,\"min\":%u,\"sec\":%u,\"dir\":\"%c\"},"
                   "\"longitude\":{\"deg\":%u,\"min\":%u,\"sec\":%u,\"dir\":\"%c\"}"
                   "},\"ts\":%.0f}}",
                   g_latest.light, g_latest.motion, g_latest.temp, g_latest.hum,
                   g_latest.lat_deg, g_latest.lat_min, g_latest.lat_sec, g_latest.lat_hem ? g_latest.lat_hem : '?',
                   g_latest.lon_deg, g_latest.lon_min, g_latest.lon_sec, g_latest.lon_hem ? g_latest.lon_hem : '?',
                   g_latest.ts);
          mg_websocket_write(ctx, "/ws", response, strlen(response));
        }
        pthread_mutex_unlock(&g_lock);
      }
      have = 0;
      printf("Giải mã và gửi dữ liệu mất %f giây\n", (double)(clock() - start) / CLOCKS_PER_SEC);
    }
  }

  pclose(fp);
  return NULL;
}

// ====== HTTP handlers ======
static int h_api_latest(struct mg_connection *c, void *cb) {
  (void)cb;
  clock_t start = clock();
  pthread_mutex_lock(&g_lock);
  latest_t L = g_latest;
  pthread_mutex_unlock(&g_lock);

  mg_printf(c,
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Cache-Control: no-store\r\n"
    "Access-Control-Allow-Origin: *\r\n"
    "Access-Control-Allow-Credentials: false\r\n"
    "\r\n");

  if (!L.has_data) {
    mg_printf(c, "{\"ok\":true,\"data\":null}");
    printf("Phản hồi /api/latest (no data) mất %f giây\n", (double)(clock() - start) / CLOCKS_PER_SEC);
    return 200;
  }

  mg_printf(c,
    "{"
      "\"ok\":true,"
      "\"data\":{"
        "\"ts\":%.0f,"
        "\"parsed\":{"
          "\"light\":%u,"
          "\"motion\":%u,"
          "\"temperature\":%u,"
          "\"humidity\":%u,"
          "\"latitude\":{\"deg\":%u,\"min\":%u,\"sec\":%u,\"dir\":\"%c\"},"
          "\"longitude\":{\"deg\":%u,\"min\":%u,\"sec\":%u,\"dir\":\"%c\"}"
        "}"
      "}"
    "}",
    L.ts, L.light, L.motion, L.temp, L.hum,
    L.lat_deg, L.lat_min, L.lat_sec, L.lat_hem ? L.lat_hem : '?',
    L.lon_deg, L.lon_min, L.lon_sec, L.lon_hem ? L.lon_hem : '?');
  printf("Phản hồi /api/latest mất %f giây\n", (double)(clock() - start) / CLOCKS_PER_SEC);
  return 200;
}

static int h_api_login(struct mg_connection *c, void *cb) {
  (void)cb;
  char body[1024];
  read_body(c, body, sizeof(body));

  char username[128] = {0}, password[128] = {0};
  json_get_string(body, "username", username, sizeof(username));
  json_get_string(body, "password", password, sizeof(password));

  int ok = 0;
  if (strcmp(username, OK_USER) == 0) {
    pthread_mutex_lock(&g_pwd_lock);
    ok = (strcmp(password, g_password) == 0);
    pthread_mutex_unlock(&g_pwd_lock);
  }

  if (ok) {
    gen_token();
    mg_printf(c,
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: application/json\r\n"
      "Set-Cookie: sid=%s; HttpOnly; Path=/\r\n"
      "\r\n"
      "{\"ok\":true}", SESSION_TOKEN);
  } else {
    mg_printf(c,
      "HTTP/1.1 401 Unauthorized\r\n"
      "Content-Type: application/json\r\n"
      "\r\n"
      "{\"ok\":false,\"error\":\"bad_credentials\"}");
  }
  return 200;
}

static int h_api_logout(struct mg_connection *c, void *cb) {
  (void)cb;
  mg_printf(c,
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Set-Cookie: sid=; Max-Age=0; Path=/\r\n"
    "\r\n"
    "{\"ok\":true}");
  return 200;
}

static int h_api_change_password(struct mg_connection *c, void *cb) {
  (void)cb;
  if (!is_logged_in(c)) {
    mg_printf(c, "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{\"ok\":false,\"error\":\"unauthorized\"}");
    return 401;
  }

  char body[1024];
  read_body(c, body, sizeof(body));

  char oldp[128] = {0}, newp[128] = {0};
  json_get_string(body, "old_password", oldp, sizeof(oldp));
  json_get_string(body, "new_password", newp, sizeof(newp));

  int ok_old = 0;
  pthread_mutex_lock(&g_pwd_lock);
  ok_old = (strcmp(oldp, g_password) == 0);
  if (!ok_old) {
    pthread_mutex_unlock(&g_pwd_lock);
    mg_printf(c, "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"ok\":false,\"error\":\"wrong_old_password\"}");
    return 200;
  }

  if (strlen(newp) < 6) {
    pthread_mutex_unlock(&g_pwd_lock);
    mg_printf(c, "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"ok\":false,\"error\":\"weak_password\"}");
    return 200;
  }

  strncpy(g_password, newp, sizeof(g_password)-1);
  g_password[sizeof(g_password)-1] = 0;
  pthread_mutex_unlock(&g_pwd_lock);

  mg_printf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}");
  return 200;
}

static int h_static(struct mg_connection *c, void *cb) { 
  (void)c; (void)cb; 
  return 0; 
}

int main(int argc, char **argv) {
  clock_t start = clock();
  if (argc > 1) SERIAL_DEV = argv[1];
  srand((unsigned)time(NULL));

  // 1) start reader thread
  struct mg_context *ctx = NULL;
  pthread_t th;
  if (pthread_create(&th, NULL, reader_thread, (void*)ctx) != 0) {
    fprintf(stderr, "Lỗi pthread_create: %s\n", strerror(errno));
    return 1;
  }

  // 2) start HTTP server
  const char *options[] = {
    "document_root", DOCROOT,
    "listening_ports", LISTEN_ADDR,
    "enable_directory_listing", "no",
    0
  };
  struct mg_callbacks cb;
  memset(&cb, 0, sizeof(cb));
  ctx = mg_start(&cb, NULL, options);
  if (!ctx) {
    fprintf(stderr, "Lỗi khởi động HTTP server\n");
    return 1;
  }
  printf("Khởi động HTTP server mất %f giây\n", (double)(clock() - start) / CLOCKS_PER_SEC);

  // Đăng ký WebSocket handlers
  mg_set_websocket_handler(ctx, "/ws", 
                          websocket_connect_handler,
                          websocket_ready_handler,
                          websocket_data_handler,
                          websocket_close_handler,
                          NULL);

  // API routes
  mg_set_request_handler(ctx, "/api/login", h_api_login, 0);
  mg_set_request_handler(ctx, "/api/logout", h_api_logout, 0);
  mg_set_request_handler(ctx, "/api/change_password", h_api_change_password, 0);
  mg_set_request_handler(ctx, "/api/latest", h_api_latest, 0);
  mg_set_request_handler(ctx, "/", h_static, 0);

  fprintf(stderr, "Bảng điều khiển tại http://%s (docroot=%s)\n", LISTEN_ADDR, DOCROOT);
  fprintf(stderr, "Đang chạy: ./test1 %s\n", SERIAL_DEV);

  // 3) loop forever
  while (1) { usleep(1000 * 1000); }
  mg_stop(ctx);
  return 0;
}

