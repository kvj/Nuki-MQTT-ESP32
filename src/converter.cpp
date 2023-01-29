#include <ArduinoJson.h>
#include <Logger.h>
#include <map>

#include "util.h"
#include "net.h"

static std::map<unsigned char, std::string> lock_action_map {
    {0x01, "unlock"},
    {0x02, "lock"},
    {0x03, "unlatch"},
    {0x04, "lock_n_go"},
    {0x05, "lock_n_go_unlatch"},
    {0x06, "full_lock"},
    {0x81, "fob_action_1"},
    {0x82, "fob_action_2"},
    {0x83, "fob_action_3"},
};

static std::map<std::string, unsigned char> lock_action_reversed_map {
    {"unlock", 0x01},
    {"lock", 0x02},
    {"unlatch", 0x03},
    {"lock_n_go", 0x04},
    {"lock_n_go_unlatch", 0x05},
    {"full_lock", 0x06},
    {"fob_action_1", 0x81},
    {"fob_action_2", 0x82},
    {"fob_action_3", 0x83},
};

static std::map<unsigned char, std::string> lock_state_map {
    {0x00, "uncalibrated"},
    {0x01, "locked"},
    {0x02, "unlocking"},
    {0x03, "unlocked"},
    {0x04, "locking"},
    {0x05, "unlatched"},
    {0x06, "unlocked_lock_n_go"},
    {0x07, "unlatching"},
    {0xfc, "calibration"},
    {0xfd, "boot_run"},
    {0xfe, "motor_blocked"},
    {0xff, "undefined"},
};

static std::map<unsigned char, std::string> lock_fob_action_map {
    {0x00, "no_action"},
    {0x01, "unlock"},
    {0x02, "lock"},
    {0x03, "lock_n_go"},
    {0x04, "intelligent"},
};

static std::map<unsigned char, std::string> error_map {
    {0xfd, "ERROR_BAD_CRC"},
    {0xfe, "ERROR_BAD_LENGTH"},
    {0xff, "ERROR_UNKNOWN"},
    {0x10, "P_ERROR_NOT_PAIRING"},
    {0x11, "P_ERROR_BAD_AUTHENTICATOR"},
    {0x12, "P_ERROR_BAD_PARAMETER"},
    {0x13, "P_ERROR_MAX_USER"},
    {0x20, "K_ERROR_NOT_AUTHORIZED"},
    {0x21, "K_ERROR_BAD_PIN"},
    {0x22, "K_ERROR_BAD_NONCE"},
    {0x23, "K_ERROR_BAD_PARAMETER"},
    {0x24, "K_ERROR_INVALID_AUTH_ID"},
    {0x25, "K_ERROR_DISABLED"},
    {0x26, "K_ERROR_REMOTE_NOT_ALLOWED"},
    {0x27, "K_ERROR_TIME_NOT_ALLOWED"},
    {0x28, "K_ERROR_TOO_MANY_PIN_ATTEMPTS"},
    {0x29, "K_ERROR_TOO_MANY_ENTRIES"},
    {0x2a, "K_ERROR_CODE_ALREADY_EXISTS"},
    {0x2b, "K_ERROR_CODE_INVALID"},
    {0x2c, "K_ERROR_CODE_INVALID_TIMEOUT_1"},
    {0x2d, "K_ERROR_CODE_INVALID_TIMEOUT_2"},
    {0x2e, "K_ERROR_CODE_INVALID_TIMEOUT_3"},
    {0x40, "K_ERROR_AUTO_UNLOCK_TOO_RECENT"},
    {0x41, "K_ERROR_POSITION_UNKNOWN"},
    {0x42, "K_ERROR_MOTOR_BLOCKED"},
    {0x43, "K_ERROR_CLUTCH_FAILURE"},
    {0x44, "K_ERROR_MOTOR_TIMEOUT"},
    {0x45, "K_ERROR_BUSY"},
    {0x46, "K_ERROR_CANCELED"},
    {0x47, "K_ERROR_NOT_CALIBRATED"},
    {0x48, "K_ERROR_MOTOR_POSITION_LIMIT"},
    {0x49, "K_ERROR_MOTOR_LOW_VOLTAGE"},
    {0x4a, "K_ERROR_MOTOR_POWER_FAILURE"},
    {0x4b, "K_ERROR_CLUTCH_POWER_FAILURE"},
    {0x4c, "K_ERROR_VOLTAGE_TOO_LOW"},
    {0x4d, "K_ERROR_FIRMWARE_UPDATE_NEEDED"},
    {0x01, "ERROR_PROTOCOL_BAD_LENGTH"},
    {0x02, "ERROR_PROTOCOL_UNEXPECTED_COMMAND"},
};

static const auto unk_str = std::string("unknown");

template <class K, class V>
V find_in_map(std::map<K, V> map, K key, V default_value) {
    auto search = map.find(key);
    if (search != map.end()) {
        return search->second;
    }
    return default_value;
}

bool to_date_time_str(JsonDocument *doc, unsigned char *in, const char *name, bool with_tz) {
    // yyyy-mm-ddThh:mm:ss+hh:mm
    const char zeros[] = "\x00\x00\x00\x00\x00\x00\x00";
    if (memcmp(in, &zeros, 7) == 0) {
        return false;
    }
    char outp[19];
    unsigned short year;
    memcpy(&year, in, 2);
    sprintf((char *)&outp, "%04u-%02u-%02uT%02u:%02u:%02u", year, in[2], in[3], in[4], in[5], in[6]);
    auto outp_str = std::string(outp, 19);
    if (with_tz) {
        char outp[6];
        short tz_offset;
        memcpy(&tz_offset, &in[7], 2);
        if (tz_offset < 0) {
            sprintf((char *)&outp, "%02d:%02u", floor(tz_offset / 60), tz_offset % 60);
        } else {
            sprintf((char *)&outp, "+%02u:%02u", ceil(tz_offset / 60), tz_offset % 60);
        }
        outp_str += std::string(outp, 6);
    } else {
        outp_str += "+00:00";
    }
    (*doc)[name] = outp_str;
    return true;
}

bool to_hour_minute_str(JsonDocument *doc, unsigned char *in, const char *name) {
    // hh:mm
    const char zeros[] = "\x00\x00";
    if (memcmp(in, &zeros, 2) == 0) {
        return false;
    }
    char outp[5];
    sprintf((char *)&outp, "%02u:%02u", in[0], in[1]);
    auto outp_str = std::string((char *)&outp, 5);
    (*doc)[name] = outp_str;
    return true;
}

static std::map<unsigned char, std::string> trigger_map {
    {0x00, "system"},
    {0x01, "manual"},
    {0x02, "button"},
    {0x03, "automatic"},
};

static std::map<unsigned char, std::string> door_sensor_map {
    {0x00, "unavailable"},
    {0x01, "deactivated"},
    {0x02, "door_closed"},
    {0x03, "door_opened"},
    {0x04, "door_state_unknown"},
    {0x05, "calibrating"},
};

void convert_state_to_json(unsigned char type, unsigned char *in, std::string *out) {
    // 0 02
    // 1 03
    // 2 00
    // 3 e6070907071909
    // 10 0000
    // 12 9c
    // 13 1b
    // 14 00
    // 15 03
    // 16 00
    // 17 00
    // 18 04
    // 19 00
    // 20 01
    StaticJsonDocument<512> doc;
    doc["trigger"] = find_in_map(trigger_map, in[2], unk_str);
    to_date_time_str(&doc, &in[3], "current_time", true);
    if (type == 0) {
        doc["state"] = find_in_map(lock_state_map, in[1], unk_str);
        doc["bat_critical"] = (in[12] & 1) != 0;
        doc["bat_charging"] = (in[12] & 2) != 0;
        doc["bat_level"] = (in[12] >> 2) * 2;
        doc["last_action"] = find_in_map(lock_action_map, in[15], unk_str);
        doc["last_action_trigger"] = find_in_map(trigger_map, in[16], unk_str);
        doc["door_sensor"] = find_in_map(door_sensor_map, in[18], unk_str);
        doc["night_mode"] = in[19] != 0;
        doc["acc_bat_supported"] = (in[20] & 1) != 0;
        doc["acc_bat_critical"] = (in[20] & 2) != 0;
    }
    serializeJson(doc, *out);
}

std::string version_to_string(unsigned char *in, int len) {
    auto result = std::to_string(in[0]);
    for (int i = 1; i < len; i++) {
        result += "." + std::to_string(in[i]);
    }
    return result;
}

std::string convert_config_to_json(unsigned char type, unsigned char *in) {
    StaticJsonDocument<512> doc;
    unsigned int id;
    memcpy(&id, in, 4);
    doc["id"] = id;
    doc["name"] = std::string((char *)&in[4]);
    float lat, lon;
    memcpy(&lat, &in[36], 4);
    memcpy(&lon, &in[40], 4);
    doc["lat"] = lat;
    doc["lon"] = lon;
    if (type == 0) {
        // 3401f628 - 4
        // 46726f6e7420446f6f7200000000000000000000000000000000000000000000 - 36 / 32
        // 53025142 - 40 / 36
        // 22784d41 - 44 / 40
        // 0101010001 - 49 / 45
        // e60709080f1a2b0000 - 58
        // 0000040102000001 - 66
        // 020c04 - 69
        // 0b01 - 71
        // 01 - 72
        // 2500
        doc["auto_unlatch"] = in[44] != 0;
        doc["pairing_enabled"] = in[45] != 0;
        doc["button_enabled"] = in[46] != 0;
        doc["led_enabled"] = in[47] != 0;
        doc["led_brightness"] = in[48];
        to_date_time_str(&doc, &in[49], "current_time", true);
        doc["dst_mode"] = in[58] == 0? "disabled": "european";
        doc["has_fob"] = in[59] != 0;
        doc["fob_action1"] = find_in_map(lock_fob_action_map, in[60], std::string("unknown"));
        doc["fob_action2"] = find_in_map(lock_fob_action_map, in[61], std::string("unknown"));
        doc["fob_action3"] = find_in_map(lock_fob_action_map, in[62], std::string("unknown"));
        doc["single_lock"] = in[63] != 0;
        doc["advertising_mode"] = in[64] != 0;
        doc["has_keypad"] = in[65] != 0;
        doc["sw_version"] = version_to_string(&in[66], 3);
        doc["hw_version"] = version_to_string(&in[69], 2);
        unsigned short timezone_id;
        memcpy(&timezone_id, &in[72], 2);
        doc["timezone_id"] = timezone_id;
    }
    std::string out;
    serializeJson(doc, out);
    return out;
}

int convert_config_from_json(unsigned char type, unsigned char *in, char *json, unsigned char *out) {
    StaticJsonDocument<1024> doc;
    deserializeJson(doc, json);
    if (type == 0) {
        if (doc.containsKey("name")) {
            memset(&in[4], 0, 32);
            std::string name = doc["name"];
            strcpy((char *)&in[4], name.c_str());
        }
        if (doc.containsKey("auto_unlatch")) {
            in[44] = doc["auto_unlatch"]? 1: 0;
        }
        if (doc.containsKey("led_enabled")) {
            in[47] = doc["led_enabled"]? 1: 0;
        }
        if (doc.containsKey("led_brightness")) {
            in[48] = (unsigned char)doc["led_brightness"];
        }
        if (doc.containsKey("single_lock")) {
            in[63] = doc["single_lock"]? 1: 0;
        }
        memcpy(out, &in[4], 45); // Skip time
        memcpy(&out[45], &in[56], 3); // Skip has fob
        memcpy(&out[48], &in[62], 5); // Skip the rest
        memcpy(&out[53], &in[72], 2);
        return 55;
    }
    return 0;
}

int convert_keypad_code_from_json(unsigned char type, unsigned char *in, char *json, unsigned char *out) {
    StaticJsonDocument<1024> doc;
    deserializeJson(doc, json);
    if (doc.containsKey("code")) {
        unsigned int code = doc["code"];
        memcpy(&in[2], &code, 4);
    }
    if (doc.containsKey("name")) {
        memset(&in[6], 0, 20);
        std::string name = doc["name"];
        strcpy((char *)&in[6], name.c_str());
    }
    if (doc.containsKey("enabled")) {
        bool flag = doc["enabled"];
        in[26] = flag? 1: 0;
    }
    memcpy(out, in, 27);
    memcpy(&out[27], &in[43], 20);
    return 47;
}

unsigned char convert_action_from_json(unsigned char type, char *in) {
    StaticJsonDocument<256> doc;
    deserializeJson(doc, in);
    std::string action = doc["action"];
    unsigned char default_action = 0;
    return find_in_map(lock_action_reversed_map, action, default_action);
}

void convert_pin_from_json(unsigned char type, char *in, unsigned short *out) {
    StaticJsonDocument<32> doc;
    deserializeJson(doc, in);
    unsigned short pin = doc["pin"];
    memcpy(out, &pin, 2);
}

std::string convert_info_to_json(unsigned char type, const char *address, bool paired, unsigned short pin) {
    StaticJsonDocument<128> doc;
    doc["address"] = std::string(address);
    doc["pairing_complete"] = paired;
    doc["pin"] = pin;
    doc["version"] = NUKI_MQTT_VER;
    doc["base_topic"] = net_build_topic("");
    std::string out;
    serializeJson(doc, out);
    return out;
}

void convert_error_to_json(unsigned char type, unsigned char code, std::string *out) {
    StaticJsonDocument<128> doc;
    doc["code"] = code;
    doc["message"] = find_in_map(error_map, code, std::string("ERROR_UNKNOWN_CODE"));
    serializeJson(doc, *out);
}

std::string convert_connection_status_to_json(unsigned char type, bool connected, int rssi) {
    StaticJsonDocument<128> doc;
    doc["connected"] = connected;
    if (connected) {
        doc["rssi"] = rssi;
    }
    std::string out = "";
    serializeJson(doc, out);
    return out;
}

static std::map<unsigned char, std::string> authorization_type_map {
    {0x00, "app"},
    {0x01, "bridge"},
    {0x02, "fob"},
    {0x03, "keypad"},
};

std::string convert_authorizations_to_json(unsigned char type, unsigned char *in) {
    // df5c3400 - 4
    // 03 - 5
    // 4e756b69204b6579706164000000000000000000000000000000000000000000 - 37
    // 0100 - 39
    // e50707180b1b1a - 46
    // e607090a061a26 - 53
    // 8f07 - 55
    // 00 - 56
    // 00000000000000 - 63
    // 00000000000000 - 70
    // 00 - 71
    // 0000 - 73
    // 0000 - 75
    StaticJsonDocument<256> doc;
    unsigned int id;
    memcpy(&id, in, 4);
    doc["id"] = id;
    doc["type"] = find_in_map(authorization_type_map, in[4], std::string("unknown"));
    doc["name"] = std::string((char *)&in[5]);
    doc["enabled"]= in[37] != 0;
    doc["remote_allowed"]= in[38] != 0;
    to_date_time_str(&doc, &in[39], "created", false);
    to_date_time_str(&doc, &in[46], "updated", false);
    unsigned short lock_count = 0;
    memcpy(&lock_count, &in[53], 2);
    doc["lock_count"] = lock_count;
    doc["time_limited"]= in[55] != 0;
    to_date_time_str(&doc, &in[56], "allowed_from", false);
    to_date_time_str(&doc, &in[63], "allowed_until", false);
    doc["week_days_mask"]= in[70];
    to_hour_minute_str(&doc, &in[71], "time_from");
    to_hour_minute_str(&doc, &in[73], "time_until");
    std::string out = "";
    serializeJson(doc, out);
    return out;
}

std::string convert_keypad_codes_to_json(unsigned char type, unsigned char *in) {
    // 0100 2
    // 87d60500 6
    // 456e74727920636f646500000000000000000000 26
    // 01 27
    // e50707180b1c06 34
    // e5070814052518 41
    // 0700 43
    // 00 44
    // 00000000000000 51
    // 00000000000000 58
    // 00 59
    // 0000 61
    // 0000 63
    StaticJsonDocument<256> doc;
    unsigned short id;
    memcpy(&id, in, 2);
    doc["id"] = id;
    unsigned int code;
    memcpy(&code, &in[2], 4);
    doc["code"] = code;
    doc["name"] = std::string((char *)&in[6]);
    doc["enabled"]= in[26] != 0;
    to_date_time_str(&doc, &in[27], "created", false);
    to_date_time_str(&doc, &in[34], "updated", false);
    unsigned short lock_count = 0;
    memcpy(&lock_count, &in[41], 2);
    doc["lock_count"] = lock_count;
    doc["time_limited"]= in[43] != 0;
    to_date_time_str(&doc, &in[44], "allowed_from", false);
    to_date_time_str(&doc, &in[51], "allowed_until", false);
    doc["week_days_mask"]= in[58];
    to_hour_minute_str(&doc, &in[59], "time_from");
    to_hour_minute_str(&doc, &in[61], "time_until");
    std::string out = "";
    serializeJson(doc, out);
    return out;
}

static std::map<unsigned char, std::string> lock_log_type_map {
    {0x01, "logging"},
    {0x02, "lock"},
    {0x03, "calibration"},
    {0x04, "initialization"},
    {0x05, "keypad"},
    {0x06, "door"},
    {0x07, "door_logging"},
};

static std::map<unsigned char, std::string> action_status_map {
    {0x00, "success"},
    {0x01, "motor_blocked"},
    {0x02, "canceled"},
    {0x03, "too_recent"},
    {0x04, "busy"},
    {0x05, "low_voltage"},
    {0x06, "clutch_failure"},
    {0x07, "motor_power_failure"},
    {0x08, "incomplete_failure"},
    {0xfe, "other_error"},
    {0xff, "unknown_error"},
    {0xe0, "invalid_code"},
};

std::string convert_log_entry_to_json(unsigned char type, unsigned char *in) {
    StaticJsonDocument<256> doc;
    // c02d0000 4 
    // e607091a040d15 11
    // ff5c3400 15
    // 4e756b69204d5154540000000000000000000000000000000000000000000000 47
    // 02 48
    // 03000000 52
    // 0062c80000 57

    to_date_time_str(&doc, &in[4], "timestamp", false);
    unsigned int id;
    memcpy(&id, &in[11], 4);
    doc["auth_id"] = id;
    doc["name"] = std::string((char *)&in[15]);

    if (type == 0) {
        doc["type"] = find_in_map(lock_log_type_map, in[47], unk_str);
    }
    if (in[47] == 0x02) { // Lock action
        doc["action"] = find_in_map(lock_action_map, in[48], unk_str);
        doc["trigger"] = find_in_map(trigger_map, in[49], unk_str);
        doc["status"] = find_in_map(action_status_map, in[51], unk_str);
        doc["type"] = "action";
    } 
    if (in[47] == 0x05) { // Keypad action
        doc["action"] = find_in_map(lock_action_map, in[48], unk_str);
        unsigned char source = in[49];
        doc["source"] = (source == 0)? "arrow": "code";
        doc["status"] = find_in_map(action_status_map, in[50], unk_str);
        unsigned short code = 0;
        memcpy(&code, &in[51], 2);
        doc["code_id"] = code;
        doc["type"] = "keypad_code";
    } 
    std::string out = "";
    serializeJson(doc, out);
    return out;
}

unsigned int extract_id_from_data(unsigned char *in, int size) {
    unsigned int result = 0;
    memcpy(&result, in, size);
    return result;
}

unsigned int extract_id_from_json(const char *in) {
    StaticJsonDocument<256> doc;
    deserializeJson(doc, in);
    unsigned int result = doc["id"];
    return result;
}