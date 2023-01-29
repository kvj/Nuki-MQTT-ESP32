#include "net.h"

#include <Logger.h>
#include <queue>

#include "util.h"
#include "config.h"

esp_mqtt_client_config_t mqtt_cfg;
esp_mqtt_client_handle_t mqtt_client;
String topic_prefix;
bool is_connected = false;

std::string lwt_topic;
std::string lwt_message;


std::queue<p_net_msg_queue_payload> msg_queue;
std::queue<p_net_msg_queue_payload> outbox_queue;

net_request_fn request_listener = NULL;
net_connected_fn connected_listener = NULL;

bool net_is_connected() {
    return is_connected;
}

void wifi_connected(WiFiEvent_t event) {
    Logger::notice("wifi()", "Connected to WiFi network");
}

void wifi_address_acquired(WiFiEvent_t event) {
    auto log = String("IP Address: ");
    log += WiFi.localIP().toString();
    Logger::notice("wifi()", log.c_str());
}

void wifi_connect() {
    auto log = String("Connecting to WiFi network: ") + String(CONFIG_WIFI_NAME) + " ...";
    Logger::notice("wifi()", log.c_str());
    log = String("WiFi password: ") + String(CONFIG_WIFI_PASSWORD);
    Logger::verbose("wifi()", log.c_str());
    WiFi.begin(CONFIG_WIFI_NAME, CONFIG_WIFI_PASSWORD);
}

void wifi_disconnected(WiFiEvent_t event, WiFiEventInfo_t info) {
    Logger::notice("wifi()", "Disconnected from WiFi network. Will re-connect");
    wifi_connect();
}

void net_mqtt_subscribe(const char *topic) {
    esp_mqtt_client_subscribe(mqtt_client, topic, 0);
}

void mqtt_connected(void *, esp_event_base_t, int32_t, void *) {
    Logger::notice("mqtt()", "Connected to the MQTT server");
    esp_mqtt_client_subscribe(mqtt_client, String(topic_prefix + "state/get").c_str(), 0);
    esp_mqtt_client_subscribe(mqtt_client, String(topic_prefix + "config/get").c_str(), 0);
    esp_mqtt_client_subscribe(mqtt_client, String(topic_prefix + "config/set").c_str(), 0);
    esp_mqtt_client_subscribe(mqtt_client, String(topic_prefix + "action/set").c_str(), 0);
    esp_mqtt_client_subscribe(mqtt_client, String(topic_prefix + "pin/set").c_str(), 0);
    esp_mqtt_client_subscribe(mqtt_client, String(topic_prefix + "authorizations/get").c_str(), 0);
    esp_mqtt_client_subscribe(mqtt_client, String(topic_prefix + "authorizations/set").c_str(), 0);
    esp_mqtt_client_subscribe(mqtt_client, String(topic_prefix + "advanced_config/get").c_str(), 0);
    esp_mqtt_client_subscribe(mqtt_client, String(topic_prefix + "advanced_config/set").c_str(), 0);
    esp_mqtt_client_subscribe(mqtt_client, String(topic_prefix + "keypad_codes/get").c_str(), 0);
    esp_mqtt_client_subscribe(mqtt_client, String(topic_prefix + "keypad_codes/set").c_str(), 0);
    esp_mqtt_client_subscribe(mqtt_client, String(topic_prefix + "pairing/set").c_str(), 0);
    // net_mqtt_publish(lwt_topic.c_str(), lwt_message.c_str(), true);
    is_connected = true;
    if (connected_listener)
        connected_listener();
}

void mqtt_disconnected(void *, esp_event_base_t, int32_t, void *) {
    Logger::notice("mqtt()", "Disconnected from the MQTT server");
    is_connected = false;
}

void mqtt_received(void *, esp_event_base_t, int32_t, void *event_data) {
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;
    Logger::verbose("mqtt()", "New message from the MQTT server");
    auto event_topic = String(event->topic, event->topic_len);
    if (event_topic.startsWith(topic_prefix))
        event_topic = event_topic.substring(topic_prefix.length());
    auto payload = String("");
    if (event->data_len > 0)
        payload = String(event->data, event->data_len);
    auto log = String("New MQTT command: ") + event_topic + ", " + payload;
    Logger::verbose("mqtt()", log.c_str());
    auto p_payload = new net_msg_queue_payload;
    p_payload->topic = (char *)malloc(event_topic.length() + 1);
    p_payload->payload = (char *)malloc(payload.length() + 1);
    strcpy(p_payload->topic, event_topic.c_str());
    strcpy(p_payload->payload, payload.c_str());
    msg_queue.push(p_payload);
}

void net_init(const char *device_address, const char *lwt_t, const char *lwt_msg, net_connected_fn connected_fn) {
    auto addr = convert_mac_id(device_address);
    topic_prefix = String(CONFIG_MQTT_PATH) + String("/") + addr + String("/");
    connected_listener = connected_fn;
    lwt_topic = net_build_topic(lwt_t);
    lwt_message = lwt_msg;


    WiFi.disconnect(true);
    WiFi.mode(WIFI_STA);

    WiFi.onEvent(wifi_connected, ARDUINO_EVENT_WIFI_STA_CONNECTED);
    WiFi.onEvent(wifi_address_acquired, ARDUINO_EVENT_WIFI_STA_GOT_IP);
    WiFi.onEvent(wifi_disconnected, ARDUINO_EVENT_WIFI_STA_DISCONNECTED);
    
    mqtt_cfg = {};
    mqtt_cfg.uri = CONFIG_MQTT_URI;
    mqtt_cfg.client_id = CONFIG_MQTT_CLIENT_ID;
    mqtt_cfg.keepalive = 15;
    mqtt_cfg.lwt_topic = lwt_topic.c_str();
    mqtt_cfg.lwt_msg = lwt_message.c_str();
    mqtt_cfg.lwt_msg_len = lwt_message.length();
    mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_register_event(mqtt_client, MQTT_EVENT_CONNECTED, mqtt_connected, NULL);
    esp_mqtt_client_register_event(mqtt_client, MQTT_EVENT_DISCONNECTED, mqtt_disconnected, NULL);
    esp_mqtt_client_register_event(mqtt_client, MQTT_EVENT_DATA, mqtt_received, NULL);

    wifi_connect();
    esp_mqtt_client_start(mqtt_client);
}

std::string net_build_topic(const char *name) {
    return (topic_prefix + name).c_str();
}

void net_mqtt_enqeue(const char *topic, const char *in) {
    auto p_payload = new net_msg_queue_payload;
    p_payload->topic = (char *)malloc(strlen(topic) + 1);
    p_payload->payload = (char *)malloc(strlen(in) + 1);
    strcpy(p_payload->topic, topic);
    strcpy(p_payload->payload, in);
    outbox_queue.push(p_payload);
}

void net_mqtt_publish(const char *topic, const char *in, bool retain, bool root) {
    std::string full_topic = root? topic: net_build_topic(topic);
    auto log  = std::string("Publishing [") + full_topic + "]: " + in;
    Logger::verbose("mqtt()", log.c_str());
    esp_mqtt_client_publish(mqtt_client, full_topic.c_str(), in, strlen(in), 0, retain);
    Logger::verbose("mqtt()", "Published");
}

void net_set_request_listener(net_request_fn request_fn) {
    request_listener = request_fn;
}

void net_free_msg_queue_payload(p_net_msg_queue_payload payload) {
    free(payload->topic);
    free(payload->payload);
    free(payload);
}

void net_loop() {
    while(!msg_queue.empty()) {
        auto p_payload = msg_queue.front();
        if (request_listener) {
            request_listener(p_payload);
        }
        msg_queue.pop();
        net_free_msg_queue_payload(p_payload);
    }
    while(!outbox_queue.empty()) {
        auto p_payload = outbox_queue.front();
        outbox_queue.pop();
        net_mqtt_publish(p_payload->topic, p_payload->payload, true, false);
        net_free_msg_queue_payload(p_payload);
    }
}

