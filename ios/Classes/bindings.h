#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef int64_t DartPort;

typedef bool (*DartPostCObjectFnType)(DartPort port_id, void *message);

typedef struct wire_uint_8_list {
  uint8_t *ptr;
  int32_t len;
} wire_uint_8_list;

typedef struct WireSyncReturnStruct {
  uint8_t *ptr;
  int32_t len;
  bool success;
} WireSyncReturnStruct;

void store_dart_post_cobject(DartPostCObjectFnType ptr);

void wire_connect_peer(int64_t port_,
                       struct wire_uint_8_list *pub_key_str,
                       struct wire_uint_8_list *peer_add_str);

void wire_list_peers(int64_t port_);

void wire_get_node_info(int64_t port_);

void wire_open_channel(int64_t port_,
                       struct wire_uint_8_list *pub_key_str,
                       struct wire_uint_8_list *peer_add_str,
                       uint64_t amount,
                       bool is_public);

void wire_list_channels(int64_t port_);

void wire_close_channel(int64_t port_,
                        struct wire_uint_8_list *channel_id_str,
                        struct wire_uint_8_list *peer_pubkey_str);

void wire_force_close_channel(int64_t port_,
                              struct wire_uint_8_list *channel_id_str,
                              struct wire_uint_8_list *peer_pubkey_str);

void wire_start_ldk(int64_t port_,
                    struct wire_uint_8_list *username,
                    struct wire_uint_8_list *password,
                    struct wire_uint_8_list *host,
                    int32_t node_network,
                    struct wire_uint_8_list *path,
                    uint16_t port);

struct wire_uint_8_list *new_uint_8_list_0(int32_t len);

void free_WireSyncReturnStruct(struct WireSyncReturnStruct val);

static int64_t dummy_method_to_enforce_bundling(void) {
    int64_t dummy_var = 0;
    dummy_var ^= ((int64_t) (void*) wire_connect_peer);
    dummy_var ^= ((int64_t) (void*) wire_list_peers);
    dummy_var ^= ((int64_t) (void*) wire_get_node_info);
    dummy_var ^= ((int64_t) (void*) wire_open_channel);
    dummy_var ^= ((int64_t) (void*) wire_list_channels);
    dummy_var ^= ((int64_t) (void*) wire_close_channel);
    dummy_var ^= ((int64_t) (void*) wire_force_close_channel);
    dummy_var ^= ((int64_t) (void*) wire_start_ldk);
    dummy_var ^= ((int64_t) (void*) new_uint_8_list_0);
    dummy_var ^= ((int64_t) (void*) free_WireSyncReturnStruct);
    dummy_var ^= ((int64_t) (void*) store_dart_post_cobject);
    return dummy_var;
}