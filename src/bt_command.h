#ifndef NUKI_BT_CMDS_H
#define NUKI_BT_CMDS_H

#include "bt.h"
#include "protocol.h"


#define COMMAND_REQUEST_STATE 1
#define COMMAND_REQUEST_CONFIG 2
#define COMMAND_REQUEST_ADV_CONFIG 4
#define COMMAND_REQUEST_AUTHORIZATIONS 8
#define COMMAND_REQUEST_KEYPAD_CODES 16

#define COMMAND_REQUEST_ALL 255

bool cmd_pair(bt_read_write_fn read_write, unsigned char *out36);
bool cmd_request_state(bt_read_write_fn read_write, unsigned char *key36);
bool cmd_lock_action(bt_read_write_fn read_write, unsigned char *key36, unsigned char action);
bool cmd_request_config(bt_read_write_fn read_write, unsigned char *key36, unsigned char *out256);
bool cmd_save_config(bt_read_write_fn read_write, unsigned char *key36, unsigned short pin, unsigned char *in, int size);

typedef std::function<void (unsigned char *in)> cmd_item_fn;
bool cmd_request_authorizations(bt_read_write_fn read_write, unsigned char *key36, unsigned short pin, cmd_item_fn item_fn);
bool cmd_request_keypad_codes(bt_read_write_fn read_write, unsigned char *key36, unsigned short pin, cmd_item_fn item_fn);
bool cmd_request_log(bt_read_write_fn read_write, unsigned char *key36, unsigned short pin, cmd_item_fn item_fn);

bool cmd_update_keypad_code(bt_read_write_fn read_write, unsigned char *key36, unsigned short pin, unsigned char *in, int size);

typedef std::function<void (unsigned char *in, int in_len)> cmd_state_change_fn;
typedef std::function<void (unsigned short code)> cmd_error_fn;
void cmd_set_listeners(cmd_state_change_fn state_change_fn, cmd_error_fn error_fn);



#endif
