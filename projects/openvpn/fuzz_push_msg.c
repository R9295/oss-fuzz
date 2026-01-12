#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#include <netdb.h>
#include <netinet/in.h>

#include "buffer.h"
#include "multi.h"
#include "options_util.h"
#include "push.h"
#include "syshead.h"

int process_incoming_push_msg_test(struct context *c,
                                   const struct buffer *buffer,
                                   bool honor_received_options,
                                   unsigned int permission_mask,
                                   unsigned int *option_types_found) {
  struct buffer buf = *buffer;

  if (buf_string_compare_advance(&buf, "PUSH_REQUEST")) {
    return PUSH_MSG_REQUEST;
  } else if (honor_received_options &&
             buf_string_compare_advance(&buf, push_reply_cmd)) {
    return PUSH_MSG_REPLY;
  } else if (honor_received_options &&
             buf_string_compare_advance(&buf, push_update_cmd)) {
    return process_push_update(c, &c->options, permission_mask, option_types_found, &buf,
                               false);
  } else {
    return PUSH_MSG_ERROR;
  }
}

static void init_fuzz_context(struct context *c) {
  memset(c, 0, sizeof(struct context));
  c->c2.es = env_set_create(NULL);
}

static void cleanup_fuzz_context(struct context *c) {
  uninit_options(&c->options);
  context_gc_free(c);
  if (c->c2.es) {
    env_set_destroy(c->c2.es);
    c->c2.es = NULL;
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 256 || size == 0) {
    return 0;
  }

  struct context c;
  init_fuzz_context(&c);
  init_options(&c.options, true);
  c.options.pull = true;
  c.options.disable_dco = true;
  c.options.route_nopull = false;
  c.options.pull_filter_list = NULL;
  net_ctx_init(&c, &c.net_ctx);
  init_verb_mute(&c, IVM_LEVEL_1);

  init_options_dev(&c.options);

  struct buffer buf = alloc_buf(size + 1);
  if (!buf_write(&buf, data, size)) {
    free_buf(&buf);
    cleanup_fuzz_context(&c);
    return 0;
  }

  uint8_t *buf_data = BPTR(&buf);
  if (buf_data && BLEN(&buf) > 0) {
    if (buf.capacity > (int)size) {
      buf_data[size] = '\0';
    }
  }

  /* Reset buffer position for reading */
  buf.offset = 0;
  buf.len = size;

  unsigned int option_types_found = 0;
  const unsigned int permission_mask_all = ~0;
  process_incoming_push_msg_test(&c, &buf, true, permission_mask_all,
                                 &option_types_found);

  free_buf(&buf);
  cleanup_fuzz_context(&c);

  return 0;
}
