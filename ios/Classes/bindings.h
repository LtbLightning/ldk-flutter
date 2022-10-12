#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct wire_uint_8_list {
  uint8_t *ptr;
  int32_t len;
} wire_uint_8_list;

typedef struct WireSyncReturnStruct {
  uint8_t *ptr;
  int32_t len;
  bool success;
} WireSyncReturnStruct;

typedef int64_t DartPort;

typedef bool (*DartPostCObjectFnType)(DartPort port_id, void *message);

void wire_start_ldk(int64_t port_,
                    struct wire_uint_8_list *username,
                    struct wire_uint_8_list *password,
                    struct wire_uint_8_list *host,
                    struct wire_uint_8_list *node_network,
                    struct wire_uint_8_list *path,
                    uint16_t port);

void wire_open_channel(int64_t port_,
                       struct wire_uint_8_list *pub_key_str,
                       struct wire_uint_8_list *peer_add_str,
                       uint64_t amount,
                       bool is_public);

struct wire_uint_8_list *new_uint_8_list_0(int32_t len);

void free_WireSyncReturnStruct(struct WireSyncReturnStruct val);

void store_dart_post_cobject(DartPostCObjectFnType ptr);

static int64_t dummy_method_to_enforce_bundling(void) {
    int64_t dummy_var = 0;
    dummy_var ^= ((int64_t) (void*) wire_start_ldk);
    dummy_var ^= ((int64_t) (void*) wire_open_channel);
    dummy_var ^= ((int64_t) (void*) new_uint_8_list_0);
    dummy_var ^= ((int64_t) (void*) free_WireSyncReturnStruct);
    dummy_var ^= ((int64_t) (void*) store_dart_post_cobject);
    return dummy_var;
}