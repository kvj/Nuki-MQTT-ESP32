#ifndef NUKI_BT_H

#include <NimBLEDevice.h>

#define SERVICE_GDIO 1
#define SERVICE_USDIO 2

typedef std::function<void (unsigned char bit_mask)> bt_state_push_fn;
typedef std::function<void ()> bt_connected_fn;
typedef std::function<void (bool connected, int rssi)> bt_connection_status_fn;


typedef std::function<bool (unsigned char *in, int in_len)> bt_accept_fn;
typedef std::function<int (unsigned char *in, int in_len, unsigned char *out256, bt_accept_fn accept_fn)> bt_read_write_fn;
typedef std::function<void (bt_read_write_fn read_write)> bt_connect_fn;

bool bt_run(int service, bt_connect_fn on_connect, int retries = 5);

void bt_setup(const char *device_address, bt_connected_fn connected_fn);
void bt_start_scan();
int bt_connect_and_run(unsigned char *in, int in_len, unsigned char *out256);
void bt_loop();

void bt_set_listeners(bt_state_push_fn state_push_fn, bt_connection_status_fn connection_status_fn);

bool bt_is_found();

#define NUKI_BT_H
#endif