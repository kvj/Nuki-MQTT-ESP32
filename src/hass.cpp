#include "hass.h"
#include "util.h"
#include "net.h"
#include "store.h"

#include "config.h"

#include <ArduinoJson.h>
#include <Logger.h>

void append_availabiliy(JsonDocument* doc) {
    (*doc)["avty_t"] = net_build_topic("connection");
    (*doc)["avty_tpl"] = "{{iif(value_json.connected, 'online', 'offline')}}";
}

void append_bridge_device(JsonDocument* doc, std::string mac, std::string name) {
    auto obj = doc->createNestedObject("dev");
    obj["name"] = name;
    obj["mf"] = "ESP32 board";
    obj["model"] = "ESP32 Nuki MQTT bridge";
    auto connections = obj.createNestedArray("ids");
    connections.add(mac + "_nuki_bridge");
}

void append_sub_device(JsonDocument* doc, std::string mac, std::string id, std::string name, const char *type, const char *model) {
    auto obj = doc->createNestedObject("dev");
    obj["name"] = name;
    obj["mf"] = "Nuki";
    obj["model"] = model;
    auto connections = obj.createNestedArray("ids");    
    connections.add(id + "_" + type);
    obj["via_device"] = mac + "_nuki_bridge";
}

void append_lock_device(JsonDocument* doc, std::string mac, unsigned int id, std::string name) {
    append_sub_device(doc, mac, std::to_string(id), name, "nuki_device", "Lock");
}

std::string build_topic(const char *type, const char *address, const char *id) {
    return std::string(CONFIG_HASS_DISCOVERY_PREFIX) + "/" + type + "/" + convert_mac_id(address).c_str() + "/" + id;
}

std::string build_unique_id(const char *address, const char *id) {
    return std::string("nuki_mqtt_") + convert_mac_id(address).c_str() + "_" + id;
}

void hass_update_bridge(const char *address) {
    auto doc_out = StaticJsonDocument<1024>();
    auto name = std::string("Nuki MQTT Bridge ") + address;
    append_bridge_device(&doc_out, address, name);
    doc_out["object_id"] = name + " Paired";
    doc_out["name"] = "Paired";
    doc_out["stat_t"] = net_build_topic("info");
    doc_out["val_tpl"] = "{{iif(value_json.pairing_complete,'ON','OFF')}}";
    doc_out["uniq_id"] = build_unique_id(address, "paired");
    doc_out["ic"] = "mdi:bluetooth";
    doc_out["json_attr_t"] = net_build_topic("info");
    doc_out["json_attr_tpl"] = "{{value_json|tojson}}";
    std::string out = "";
    serializeJson(doc_out, out);
    net_mqtt_publish(build_topic("binary_sensor", address, "paired/config").c_str(), (char *)out.c_str(), true, true);

    doc_out = StaticJsonDocument<1024>();
    out = "";
    append_bridge_device(&doc_out, address, name);
    doc_out["object_id"] = name + " Pair";
    doc_out["name"] = "Pair";
    doc_out["cmd_t"] = net_build_topic("pairing/set");
    doc_out["cmd_tpl"] = "{}";
    doc_out["uniq_id"] = build_unique_id(address, "pair");
    doc_out["ic"] = "mdi:bluetooth-connect";
    doc_out["ent_cat"] = "config";

    serializeJson(doc_out, out);
    net_mqtt_publish(build_topic("button", address, "pair/config").c_str(), (char *)out.c_str(), true, true);

    doc_out = StaticJsonDocument<1024>();
    out = "";
    append_availabiliy(&doc_out);
    append_bridge_device(&doc_out, address, name);
    doc_out["object_id"] = name + " Last Error";
    doc_out["name"] = "Last Error";
    doc_out["uniq_id"] = build_unique_id(address, "last_error");
    doc_out["ic"] = "mdi:bluetooth-off";
    doc_out["ent_cat"] = "diagnostic";
    doc_out["stat_t"] = net_build_topic("last_error");
    doc_out["val_tpl"] = "{{value_json.message}}";

    serializeJson(doc_out, out);
    net_mqtt_publish(build_topic("sensor", address, "last_error/config").c_str(), (char *)out.c_str(), true, true);

    doc_out = StaticJsonDocument<1024>();
    out = "";
    append_availabiliy(&doc_out);
    append_bridge_device(&doc_out, address, name);
    doc_out["name"] = "PIN";
    doc_out["object_id"] = name + " PIN";
    doc_out["uniq_id"] = build_unique_id(address, "pin");
    doc_out["ic"] = "mdi:dialpad";
    doc_out["ent_cat"] = "config";
    doc_out["min"] = 0;
    doc_out["max"] = 9999;
    doc_out["mode"] = "box";
    doc_out["stat_t"] = net_build_topic("info");
    doc_out["val_tpl"] = "{{value_json.pin}}";
    doc_out["cmd_t"] = net_build_topic("pin/set");
    doc_out["cmd_tpl"] = "{\"pin\":{{value}}}";

    serializeJson(doc_out, out);
    net_mqtt_publish(build_topic("number", address, "pin/config").c_str(), (char *)out.c_str(), true, true);

    doc_out = StaticJsonDocument<1024>();
    out = "";
    append_availabiliy(&doc_out);
    append_bridge_device(&doc_out, address, name);
    doc_out["name"] = "RSSI";
    doc_out["object_id"] = name + " RSSI";
    doc_out["uniq_id"] = build_unique_id(address, "rssi");
    doc_out["dev_cla"] = "signal_strength";
    doc_out["unit_of_meas"] = "dBm";
    doc_out["ent_cat"] = "diagnostic";
    doc_out["stat_t"] = net_build_topic("connection");
    doc_out["val_tpl"] = "{{value_json.rssi|int(0)}}";

    serializeJson(doc_out, out);
    net_mqtt_publish(build_topic("sensor", address, "rssi/config").c_str(), (char *)out.c_str(), true, true);

}

void hass_update_config(int type, const char *address, unsigned char *in) {
    unsigned int id;
    memcpy(&id, in, 4);

    auto doc_out = DynamicJsonDocument(1024);
    std::string out = "";

    auto lock_name = std::string((char *)&in[4]);
    auto name = std::string("Nuki ") + lock_name;
    auto object_id = std::string("Nuki ") + std::to_string(id);

    doc_out.clear();
    out.clear();
    append_availabiliy(&doc_out);
    append_lock_device(&doc_out, address, id, name);
    doc_out["name"] = name + " Lock";
    doc_out["object_id"] = object_id + " Lock";
    doc_out["uniq_id"] = build_unique_id(address, "lock");
    doc_out["stat_t"] = net_build_topic("state");
    doc_out["val_tpl"] = "{{iif(value_json.state in ('locked'),'LOCKED','UNLOCKED')}}";
    doc_out["cmd_t"] = net_build_topic("action/set");
    doc_out["pl_open"] = "{'action': 'unlatch'}";
    doc_out["pl_lock"] = "{'action': 'lock'}";
    doc_out["pl_unlk"] = "{'action': 'unlock'}";
    doc_out["json_attr_t"] = net_build_topic("state");
    doc_out["json_attr_tpl"] = "{{value_json|tojson}}";
    doc_out["opt"] = true;

    serializeJson(doc_out, out);
    net_mqtt_publish(build_topic("lock", address, "lock/config").c_str(), (char *)out.c_str(), true, true);

    doc_out.clear();
    out.clear();
    append_availabiliy(&doc_out);
    append_lock_device(&doc_out, address, id, name);
    doc_out["name"] = name + " LED enabled";
    doc_out["object_id"] = object_id + " LED enabled";
    doc_out["uniq_id"] = build_unique_id(address, "led_enabled");
    doc_out["ic"] = "mdi:led-variant-on";
    doc_out["ent_cat"] = "config";
    doc_out["stat_t"] = net_build_topic("config");
    doc_out["val_tpl"] = "{{iif(value_json.led_enabled,'ON','OFF')}}";
    doc_out["cmd_t"] = net_build_topic("config/set");
    doc_out["state_on"] = "ON";
    doc_out["state_off"] = "OFF";
    doc_out["pl_on"] = "{'led_enabled': true}";
    doc_out["pl_off"] = "{'led_enabled': false}";
    doc_out["opt"] = true;
    serializeJson(doc_out, out);
    net_mqtt_publish(build_topic("switch", address, "led_enabled/config").c_str(), (char *)out.c_str(), true, true);
    if (type == 0) {

        doc_out.clear();
        out.clear();
        append_availabiliy(&doc_out);
        append_lock_device(&doc_out, address, id, name);
        doc_out["name"] = name + " LED brightness";
        doc_out["object_id"] = object_id + " LED brightness";
        doc_out["uniq_id"] = build_unique_id(address, "led_brightness");
        doc_out["ic"] = "mdi:brightness-6";
        doc_out["ent_cat"] = "config";
        doc_out["min"] = 0;
        doc_out["max"] = 5;
        doc_out["stat_t"] = net_build_topic("config");
        doc_out["val_tpl"] = "{{value_json.led_brightness}}";
        doc_out["cmd_t"] = net_build_topic("config/set");
        doc_out["cmd_tpl"] = "{'led_brightness': {{value}}}";
        doc_out["opt"] = true;
        serializeJson(doc_out, out);
        net_mqtt_publish(build_topic("number", address, "led_brightness/config").c_str(), (char *)out.c_str(), true, true);

        doc_out.clear();
        out.clear();
        append_availabiliy(&doc_out);
        append_lock_device(&doc_out, address, id, name);
        doc_out["name"] = name + " Battery";
        doc_out["object_id"] = object_id + " Battery";
        doc_out["uniq_id"] = build_unique_id(address, "battery");
        doc_out["stat_t"] = net_build_topic("state");
        doc_out["val_tpl"] = "{{value_json.bat_level}}";
        doc_out["dev_cla"] = "battery";
        doc_out["unit_of_meas"] = "%";
        doc_out["ent_cat"] = "diagnostic";
        serializeJson(doc_out, out);
        net_mqtt_publish(build_topic("sensor", address, "battery/config").c_str(), (char *)out.c_str(), true, true);

        doc_out.clear();
        out.clear();
        append_availabiliy(&doc_out);
        append_lock_device(&doc_out, address, id, name);
        doc_out["name"] = name + " Accessory battery critical";
        doc_out["object_id"] = object_id + " Acc battery critical";
        doc_out["uniq_id"] = build_unique_id(address, "acc_bat_critical");
        doc_out["stat_t"] = net_build_topic("state");
        doc_out["val_tpl"] = "{{iif(value_json.acc_bat_supported, iif(value_json.acc_bat_critical,'ON','OFF'), 'None')}}";
        doc_out["dev_cla"] = "battery";
        doc_out["ent_cat"] = "diagnostic";
        serializeJson(doc_out, out);
        net_mqtt_publish(build_topic("binary_sensor", address, "acc_bat_critical/config").c_str(), (char *)out.c_str(), true, true);

        doc_out.clear();
        out.clear();
        append_availabiliy(&doc_out);
        append_lock_device(&doc_out, address, id, name);
        doc_out["name"] = name + " Auto unlatch";
        doc_out["object_id"] = object_id + " Auto unlatch";
        doc_out["uniq_id"] = build_unique_id(address, "auto_unlatch");
        // doc_out["ic"] = "mdi:led-variant-on";
        doc_out["ent_cat"] = "config";
        doc_out["stat_t"] = net_build_topic("config");
        doc_out["val_tpl"] = "{{iif(value_json.auto_unlatch,'ON','OFF')}}";
        doc_out["cmd_t"] = net_build_topic("config/set");
        doc_out["state_on"] = "ON";
        doc_out["state_off"] = "OFF";
        doc_out["pl_on"] = "{'auto_unlatch': true}";
        doc_out["pl_off"] = "{'auto_unlatch': false}";
        doc_out["opt"] = true;
        serializeJson(doc_out, out);
        net_mqtt_publish(build_topic("switch", address, "auto_unlatch/config").c_str(), (char *)out.c_str(), true, true);

        doc_out.clear();
        out.clear();
        append_availabiliy(&doc_out);
        append_lock_device(&doc_out, address, id, name);
        doc_out["name"] = name + " Single lock";
        doc_out["object_id"] = object_id + " Single lock";
        doc_out["uniq_id"] = build_unique_id(address, "single_lock");
        // doc_out["ic"] = "mdi:led-variant-on";
        doc_out["ent_cat"] = "config";
        doc_out["stat_t"] = net_build_topic("config");
        doc_out["val_tpl"] = "{{iif(value_json.single_lock,'ON','OFF')}}";
        doc_out["cmd_t"] = net_build_topic("config/set");
        doc_out["state_on"] = "ON";
        doc_out["state_off"] = "OFF";
        doc_out["pl_on"] = "{'single_lock': true}";
        doc_out["pl_off"] = "{'single_lock': false}";
        doc_out["opt"] = true;
        serializeJson(doc_out, out);
        net_mqtt_publish(build_topic("switch", address, "single_lock/config").c_str(), (char *)out.c_str(), true, true);
    }
    doc_out.clear();
    out.clear();
    append_availabiliy(&doc_out);
    append_lock_device(&doc_out, address, id, name);
    doc_out["name"] = name + " Battery critical";
    doc_out["object_id"] = object_id + " Battery critical";
    doc_out["uniq_id"] = build_unique_id(address, "battery_critical");
    doc_out["stat_t"] = net_build_topic("state");
    doc_out["val_tpl"] = "{{ iif(value_json.bat_critical,'ON','OFF') }}";
    doc_out["dev_cla"] = "battery";
    doc_out["ent_cat"] = "diagnostic";

    serializeJson(doc_out, out);
    net_mqtt_publish(build_topic("binary_sensor", address, "battery_critical/config").c_str(), (char *)out.c_str(), true, true);

    doc_out.clear();
    out.clear();
    append_availabiliy(&doc_out);
    append_lock_device(&doc_out, address, id, name);
    doc_out["name"] = name + " Door";
    doc_out["object_id"] = object_id + " Door contact";
    doc_out["uniq_id"] = build_unique_id(address, "door");
    doc_out["stat_t"] = net_build_topic("state");
    doc_out["val_tpl"] = "{{ iif(value_json.door_sensor=='door_opened','ON',iif(value_json.door_sensor=='door_closed','OFF','None')) }}";
    doc_out["dev_cla"] = "door";
    doc_out["json_attr_t"] = net_build_topic("state");
    doc_out["json_attr_tpl"] = "{{{'State': value_json.door_sensor}|tojson}}";
    serializeJson(doc_out, out);
    net_mqtt_publish(build_topic("binary_sensor", address, "door/config").c_str(), (char *)out.c_str(), true, true);

    doc_out.clear();
    out.clear();
    append_availabiliy(&doc_out);
    append_lock_device(&doc_out, address, id, name);
    doc_out["name"] = name + " Firmware version";
    doc_out["object_id"] = object_id + " Firmware version";
    doc_out["uniq_id"] = build_unique_id(address, "sw_version");
    doc_out["stat_t"] = net_build_topic("config");
    doc_out["val_tpl"] = "{{value_json.sw_version}}";
    doc_out["ent_cat"] = "diagnostic";
    serializeJson(doc_out, out);
    net_mqtt_publish(build_topic("sensor", address, "sw_version/config").c_str(), (char *)out.c_str(), true, true);

    doc_out.clear();
    out.clear();
    append_availabiliy(&doc_out);
    append_lock_device(&doc_out, address, id, name);
    doc_out["name"] = name + " Hardware revision";
    doc_out["object_id"] = object_id + " Hardware revision";
    doc_out["uniq_id"] = build_unique_id(address, "hw_version");
    doc_out["stat_t"] = net_build_topic("config");
    doc_out["val_tpl"] = "{{value_json.hw_version}}";
    doc_out["ent_cat"] = "diagnostic";
    serializeJson(doc_out, out);
    net_mqtt_publish(build_topic("sensor", address, "hw_version/config").c_str(), (char *)out.c_str(), true, true);

    doc_out.clear();
    out.clear();
    append_availabiliy(&doc_out);
    append_lock_device(&doc_out, address, id, name);
    doc_out["name"] = name + " Last Action User";
    doc_out["object_id"] = object_id + " Last Action User";
    doc_out["uniq_id"] = build_unique_id(address, "last_action");
    doc_out["stat_t"] = net_build_topic("last_log");
    doc_out["val_tpl"] = "{{value_json.name}}";
    doc_out["ent_cat"] = "diagnostic";
    doc_out["ic"] = "mdi:account-lock-open";
    doc_out["json_attr_t"] = net_build_topic("last_log");
    doc_out["json_attr_tpl"] = "{{value_json|tojson}}";
    serializeJson(doc_out, out);
    net_mqtt_publish(build_topic("sensor", address, "last_action/config").c_str(), (char *)out.c_str(), true, true);
}

void hass_update_authorizations(int type, const char *address, unsigned char *in) {
    unsigned int id;
    memcpy(&id, in, 4);
    auto name = std::string((char *)&in[5]);

    auto dev_name = std::string("Nuki Authorizations");
    auto object_id = std::string("Nuki Auth ") + std::to_string(id);
    auto topic = std::string("authorizations/") + std::to_string(id);

    auto doc_out = StaticJsonDocument<1024>();
    std::string out = "";

    doc_out.clear();
    out.clear();
    append_availabiliy(&doc_out);
    append_sub_device(&doc_out, address, address, dev_name, "nuki_auth", "Authorization");
    doc_out["name"] = name;
    doc_out["object_id"] = std::string("Nuki Auth ") + std::to_string(id);
    doc_out["uniq_id"] = build_unique_id(address, (std::string("auth_") + std::to_string(id)).c_str());
    // doc_out["ic"] = "mdi:led-variant-on";
    doc_out["ent_cat"] = "config";
    doc_out["stat_t"] = net_build_topic(topic.c_str());
    doc_out["val_tpl"] = "{{iif(value_json.enabled,'ON','OFF')}}";
    doc_out["cmd_t"] = net_build_topic("authorizations/set");
    doc_out["state_on"] = "ON"; 
    doc_out["state_off"] = "OFF";
    doc_out["pl_on"] = std::string("{\"enabled\":true,\"id\":") + std::to_string(id) + "}";
    doc_out["pl_off"] = std::string("{\"enabled\":false,\"id\":") + std::to_string(id) + "}";
    doc_out["opt"] = true;
    doc_out["json_attr_t"] = net_build_topic(topic.c_str());
    doc_out["json_attr_tpl"] = "{{value_json|tojson}}";
    serializeJson(doc_out, out);
    auto config_topic = std::string("auth_") + std::to_string(id) + "/config";
    net_mqtt_publish(build_topic("switch", address, config_topic.c_str()).c_str(), (char *)out.c_str(), true, true);
}

void hass_update_keypad_codes(int type, const char *address, unsigned char *in) {
    unsigned short id;
    memcpy(&id, in, 2);
    auto name = std::string((char *)&in[6]);

    auto dev_name = std::string("Nuki Keypad Codes");
    auto topic = std::string("keypad_codes/") + std::to_string(id);

    auto doc_out = StaticJsonDocument<1024>();
    std::string out = "";

    doc_out.clear();
    out.clear();
    append_availabiliy(&doc_out);
    append_sub_device(&doc_out, address, address, dev_name, "nuki_keypad", "Keypad Code");
    doc_out["name"] = name;
    doc_out["object_id"] = std::string("Nuki Keypad code ") + std::to_string(id);
    doc_out["uniq_id"] = build_unique_id(address, (std::string("keypad_") + std::to_string(id)).c_str());
    // doc_out["ic"] = "mdi:led-variant-on";
    doc_out["ent_cat"] = "config";
    doc_out["stat_t"] = net_build_topic(topic.c_str());
    doc_out["val_tpl"] = "{{iif(value_json.enabled,'ON','OFF')}}";
    doc_out["cmd_t"] = net_build_topic("keypad_codes/set");
    doc_out["state_on"] = "ON"; 
    doc_out["state_off"] = "OFF";
    doc_out["pl_on"] = std::string("{\"enabled\":true,\"id\":") + std::to_string(id) + "}";
    doc_out["pl_off"] = std::string("{\"enabled\":false,\"id\":") + std::to_string(id) + "}";
    doc_out["opt"] = true;
    doc_out["json_attr_t"] = net_build_topic(topic.c_str());
    doc_out["json_attr_tpl"] = "{{value_json|tojson}}";
    serializeJson(doc_out, out);
    auto config_topic = std::string("keypad_code_") + std::to_string(id) + "/config";
    net_mqtt_publish(build_topic("switch", address, config_topic.c_str()).c_str(), (char *)out.c_str(), true, true);
}

template<class K>
std::set<K> removed_items(Preferences *preferences, std::set<K> new_items, const char *pref_name, int k_size) {
    unsigned char buffer[256];
    read_ids_array(preferences, pref_name, CAST_PUC &buffer, k_size);
    unsigned short size;
    memcpy(&size, &buffer, 2);
    std::set<K> result;
    for (int i = 0; i < size; i++) {
        K item;
        memcpy(&item, &buffer[2 + i * k_size], k_size);
        auto it = new_items.find(item);
        if (it == new_items.end()) {
            result.insert(item);
        }
    }
    size = new_items.size();
    memcpy(&buffer, &size, 2);
    int i = 0;
    for (auto it = new_items.begin(); it != new_items.end(); i++, it++) {
        K item = *it;
        memcpy(&buffer[2 + i * k_size], &item, k_size);
    }
    store_ids_array(preferences, pref_name, CAST_PUC &buffer, k_size);
    return result;
}

void hass_remove_missing_authorizations(Preferences *preferences, const char *address, std::set<unsigned int> ids) {
    auto removed = removed_items(preferences, ids, PREF_AUTH_IDS, 4);
    for (auto it = removed.begin(); it != removed.end(); it++) {
        auto log = std::string("To remove: ") + std::to_string(*it);
        Logger::verbose("hass_remove_missing_authorizations()", log.c_str());
        auto config_topic = std::string("auth_") + std::to_string(*it) + "/config";
        net_mqtt_publish(build_topic("switch", address, config_topic.c_str()).c_str(), "", true, true);
    }
}

void hass_remove_missing_keypad_codes(Preferences *preferences, const char *address, std::set<unsigned int> ids) {
    auto removed = removed_items(preferences, ids, PREF_KEYPAD_IDS, 4);
    for (auto it = removed.begin(); it != removed.end(); it++) {
        auto log = std::string("To remove: ") + std::to_string(*it);
        Logger::verbose("hass_remove_missing_keypad_codes()", log.c_str());
        auto config_topic = std::string("keypad_code_") + std::to_string(*it) + "/config";
        net_mqtt_publish(build_topic("switch", address, config_topic.c_str()).c_str(), "", true, true);
    }
}
