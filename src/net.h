#ifndef NUKI_NET_H

#include <WiFi.h>
#include <mqtt_client.h>

typedef struct {
    char *topic;
    char *payload;
} net_msg_queue_payload;
typedef net_msg_queue_payload *p_net_msg_queue_payload;

typedef std::function<void ()> net_connected_fn;

void net_init(const char *device_address, const char *lwt_topic, const char *lwt_msg, net_connected_fn connected_fn);

void net_loop();

void net_mqtt_publish(const char *topic, const char *in, bool retain=false, bool root=false);
void net_mqtt_enqeue(const char *topic, const char *in);

typedef std::function<void (p_net_msg_queue_payload payload)> net_request_fn;
void net_set_request_listener(net_request_fn request_fn);

bool net_is_connected();

std::string net_build_topic(const char *name);

#define NUKI_NET_H
#endif