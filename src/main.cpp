#include <Arduino.h>
#include <Logger.h>

#include <cstring>
#include <set>

#include "util.h"

#include "protocol.h"
#include "bt.h"
#include "net.h"
#include "bt_command.h"
#include <tweetnacl.h>

#include "config.h"

#include "converter.h"
#include "hass.h"
#include "store.h"

Preferences preferences;
unsigned char pairing_key[PREF_PAIRING_LEN];

unsigned long next_update = 0;

void schedule_next_update(int seconds) {
    next_update = millis() + 1000L * seconds;
}

bool is_paired() {
    return pairing_key[0] != 0;
}

void set_config(Preferences *preferences, char *in) {
    bt_run(SERVICE_USDIO, [&](bt_read_write_fn read_write) {
        unsigned char out256[256];
        bool result = cmd_request_config(read_write, CAST_PUC &pairing_key, CAST_PUC &out256);
        if (!result) return;
        unsigned char out256_2[256];
        int size = convert_config_from_json(0, CAST_PUC &out256[2], in, CAST_PUC &out256_2);
        result = cmd_save_config(read_write, CAST_PUC &pairing_key, read_pin(preferences), CAST_PUC &out256_2, size);
        if (!result) return;
        schedule_next_update(10);
    });

}

void update_keypad_code(Preferences *preferences, char *in_json) {
    auto json_id = extract_id_from_json(in_json);
    bt_run(SERVICE_USDIO, [=, &json_id](bt_read_write_fn read_write) {
        unsigned char out256[256];
        int size = 0;
        cmd_request_keypad_codes(read_write, CAST_PUC &pairing_key, read_pin(preferences), [=, &json_id, &out256, &size](unsigned char *in) {
            auto id = extract_id_from_data(in, 2);
            if (id == json_id) {
                size = convert_keypad_code_from_json(0, in, in_json, CAST_PUC &out256);
            }
        });
        if (size > 0) {
            bool result = cmd_update_keypad_code(read_write, CAST_PUC &pairing_key, read_pin(preferences), CAST_PUC &out256, size);
            if (result) schedule_next_update(10);
        } else {
            Logger::warning("update_keypad_code()", "Keypad entry not found");
        }
    });
}

void request_last_log(Preferences *preferences, bt_read_write_fn read_write) {
    bool entry_found = false;
    bool result = cmd_request_log(read_write, (unsigned char *)&pairing_key, read_pin(preferences), [&entry_found](unsigned char *in) {
        log_bytes("log_entry()", "Entry:", (char *)in, 48);
        if (((in[47] == 2) || (in[47] == 5)) && !entry_found) {
            net_mqtt_publish("last_log", convert_log_entry_to_json(0, in).c_str());
            entry_found = true;
        }
    });
}

void request_updates(Preferences *preferences, int request) {
    bt_run(SERVICE_USDIO, [&](bt_read_write_fn read_write) {
        unsigned char out256[256];
        if ((request & COMMAND_REQUEST_CONFIG) != 0) {
            bool result = cmd_request_config(read_write, (unsigned char *)&pairing_key, (unsigned char *)&out256);
            if (result) {
                hass_update_config(0, CONFIG_DEVICE_MAC, (unsigned char *)&out256[2]);
                net_mqtt_publish("config", (char *)convert_config_to_json(0, (unsigned char *)&out256[2]).c_str(), true);
            }
        }
        if ((request & COMMAND_REQUEST_AUTHORIZATIONS) != 0) {
            std::set<unsigned int> ids;
            bool result = cmd_request_authorizations(read_write, (unsigned char *)&pairing_key, read_pin(preferences), [&ids](unsigned char *in) {
                auto id = extract_id_from_data(in, 4);
                ids.insert(id);
                hass_update_authorizations(0, CONFIG_DEVICE_MAC, in);
                auto topic = String("authorizations/") + String(id);
                net_mqtt_publish(topic.c_str(), (char *)convert_authorizations_to_json(0, in).c_str());
            });
            if (result) hass_remove_missing_authorizations(preferences, CONFIG_DEVICE_MAC, ids);
        }
        if ((request & COMMAND_REQUEST_KEYPAD_CODES) != 0) {
            std::set<unsigned int> ids;
            bool result = cmd_request_keypad_codes(read_write, (unsigned char *)&pairing_key, read_pin(preferences), [&ids](unsigned char *in) {
                auto id = extract_id_from_data(in, 2);
                ids.insert(id);
                hass_update_keypad_codes(0, CONFIG_DEVICE_MAC, in);
                auto topic = String("keypad_codes/") + String(id);
                net_mqtt_publish(topic.c_str(), convert_keypad_codes_to_json(0, in).c_str());
            });
            if (result) hass_remove_missing_keypad_codes(preferences, CONFIG_DEVICE_MAC, ids);
        }

        if ((request & COMMAND_REQUEST_STATE) != 0) {
            cmd_request_state(read_write, (unsigned char *)&pairing_key);
            request_last_log(preferences, read_write);
        }
    });
}

void on_connected() {
    if (bt_is_found() && net_is_connected()) {
        auto outp = convert_info_to_json(0, CONFIG_DEVICE_MAC, is_paired(), read_pin(&preferences));
        hass_update_bridge(CONFIG_DEVICE_MAC);
        net_mqtt_publish("info", outp.c_str());
        if (is_paired()) {
            schedule_next_update(10);
        }
    }
}

void pair(Preferences *preferences) {
    bool result = bt_run(SERVICE_GDIO, [&preferences](bt_read_write_fn read_write) {
        unsigned char pairing_out[PREF_PAIRING_LEN];
        bool pair_result = cmd_pair(read_write, (unsigned char *)&pairing_out);
        if (pair_result) {
            pairing_out[PREF_PAIRING_LEN - 2] = 0; // Lock
            store_pairing_key(preferences, CAST_PUC &pairing_out);
            read_pairing_key(preferences, CAST_PUC &pairing_key);
            on_connected();
            request_updates(preferences, COMMAND_REQUEST_ALL);
        }
    });
}

void perform_lock_action(Preferences *preferences, unsigned char action) {
    bt_run(SERVICE_USDIO, [&preferences, &action](bt_read_write_fn read_write) {
        cmd_lock_action(read_write, (unsigned char *)&pairing_key, action);
        request_last_log(preferences, read_write);
    });
}

void on_bt_state(unsigned char *in, int len) {
    log_bytes("on_bt_state()", "New state to parse:", (char *)in, len);
    auto outp = std::string("");
    convert_state_to_json(0, in, &outp);
    Logger::verbose("on_bt_state()", outp.c_str());
    net_mqtt_enqeue("state", (char *)outp.c_str());
}

void on_mqtt_request(p_net_msg_queue_payload payload) {
    if (strcmp(payload->topic, "state/get") == 0) {
        request_updates(&preferences, COMMAND_REQUEST_STATE);
    }
    if (strcmp(payload->topic, "config/get") == 0) {
        request_updates(&preferences, COMMAND_REQUEST_CONFIG);
    }
    if (strcmp(payload->topic, "config/set") == 0) {
        set_config(&preferences, payload->payload);
    }
    if (strcmp(payload->topic, "authorizations/get") == 0) {
        request_updates(&preferences, COMMAND_REQUEST_AUTHORIZATIONS);
    }
    if (strcmp(payload->topic, "keypad_codes/get") == 0) {
        request_updates(&preferences, COMMAND_REQUEST_KEYPAD_CODES);
    }
    if (strcmp(payload->topic, "keypad_codes/set") == 0) {
        update_keypad_code(&preferences, payload->payload);
    }
    if (strcmp(payload->topic, "action/set") == 0) {
        unsigned char action = convert_action_from_json(0, payload->payload);
        perform_lock_action(&preferences, action);
    }
    if (strcmp(payload->topic, "pin/set") == 0) {
        unsigned short pin;
        convert_pin_from_json(0, payload->payload, &pin);
        auto log = String("PIN: ") + String(pin) + ", " + String(payload->payload);
        Logger::verbose(log.c_str());
        store_pin(&preferences, pin);
        on_connected();
    }
    if (strcmp(payload->topic, "pairing/set") == 0) {
        pair(&preferences);
    }
}

void run_test() {
  const char sl_public_key[] = "\x2F\xE5\x7D\xA3\x47\xCD\x62\x43\x15\x28\xDA\xAC\x5F\xBB\x29\x07\x30\xFF\xF6\x84\xAF\xC4\xCF\xC2\xED\x90\x99\x5F\x58\xCB\x3B\x74";
  const char private_key[] =   "\x8C\xAA\x54\x67\x23\x07\xBF\xFD\xF5\xEA\x18\x3F\xC6\x07\x15\x8D\x20\x11\xD0\x08\xEC\xA6\xA1\x08\x86\x14\xFF\x08\x53\xA5\xAA\x07";
  const char public_key[] =    "\xF8\x81\x27\xCC\xF4\x80\x23\xB5\xCB\xE9\x10\x1D\x24\xBA\xA8\xA3\x68\xDA\x94\xE8\xC2\xE3\xCD\xE2\xDE\xD2\x9C\xE9\x6A\xB5\x0C\x15";
  const char name[] = "\x4D\x61\x72\x63\x20\x28\x54\x65\x73\x74\x29";
  const char challenge1[] =    "\x6C\xD4\x16\x3D\x15\x90\x50\xC7\x98\x55\x3E\xAA\x57\xE2\x78\xA5\x79\xAF\xFC\xBC\x56\xF0\x9F\xC5\x7F\xE8\x79\xE5\x1C\x42\xDF\x17";
  const char challenge2[] =    "\xE0\x74\x2C\xFE\xA3\x9C\xB4\x61\x09\x38\x5B\xF9\x12\x86\xA3\xC0\x2F\x40\xEE\x86\xB0\xB6\x2F\xC3\x40\x33\x09\x4D\xE4\x1E\x2C\x0D";
  const char challenge3[] =    "\xEA\x47\x99\x15\x98\x2F\x13\xC6\x1D\x99\x7A\x56\x67\x8A\xD7\x77\x91\xBF\xA7\xE9\x52\x29\xA3\xDD\x34\xF8\x71\x32\xBF\x3E\x3C\x97";
  const char challenge4[] =    "\x37\x91\x7F\x1A\xF3\x1E\xC5\x94\x07\x05\xF3\x4D\x1E\x55\x50\x60\x7D\x5B\x2F\x9F\xE7\xD4\x96\xB6";

  const char my_challenge1[] = "\x52\xAF\xE0\xA6\x64\xB4\xE9\xB5\x6D\xC6\xBD\x4C\xB7\x18\xA6\xC9\xFE\xD6\xBE\x17\xA7\x41\x10\x72\xAA\x0D\x31\x53\x78\x14\x05\x77";
  
  const char encrypted_msg1[] =  "\x90\xB0\x75\x7C\xFE\xD0\x24\x30\x17\xEA\xF5\xE0\x89\xF8\x58\x3B\x98\x39\xD6\x1B\x05\x09\x24\xD2\x02\x00\x00\x00\x27\x00\xB1\x39\x38\xB6\x71\x21\xB6\xD5\x28\xE7\xDE\x20\x6B\x0D\x7C\x5A\x94\x58\x7A\x47\x1B\x33\xEB\xFB\x01\x2C\xED\x8F\x12\x61\x13\x55\x66\xED\x75\x6E\x39\x10\xB5";

  unsigned char step2[32 + 4];
  prepare_unencrypted(CMD_PUBLIC_KEY, (unsigned char *)&public_key, 32, NULL, (unsigned char *)&step2);
  log_bytes("start()", "Step2 request:", (char *)&step2, 32 + 4);
  
  unsigned char dh1[32];
  calculate_dh1((unsigned char *)&dh1, (unsigned char *)&private_key, (unsigned char *)&sl_public_key);
  log_bytes("start()", "dh1:", (char *)&dh1, 32);
  unsigned char shared_key[32];
  calculate_kdh1((unsigned char *)&dh1, (unsigned char *)&shared_key);
  log_bytes("start()", "shared key:", (char *)&shared_key, 32);

  unsigned char keys[64];
  prepare_auth_authenticator((unsigned char *)&public_key, (unsigned char *)&sl_public_key, (unsigned char *)&keys);

  unsigned char auth_auth[32];

  calculate_h1((unsigned char *)&shared_key, (unsigned char *)&keys, 64, (unsigned char *)&challenge1, (unsigned char *)&auth_auth);
  log_bytes("start()", "auth_auth:", (char *)&auth_auth, 32);

  unsigned char step3[32 + 4];
  prepare_unencrypted(CMD_AUTH_AUTHENTICATOR, (unsigned char *)&auth_auth, 32, NULL, (unsigned char *)&step3);
  log_bytes("start()", "Step3 request:", (char *)&step3, 32 + 4);

  unsigned char auth_data_payload[69];
  prepare_auth_data(0, 0, (char *)&name, (unsigned char *)&my_challenge1, (unsigned char *)&auth_data_payload);
  log_bytes("start()", "auth_data_payload:", (char *)&auth_data_payload, 69);

  unsigned char auth_data[32];
  calculate_h1((unsigned char *)&shared_key, (unsigned char *)&auth_data_payload, 69, (unsigned char *)&challenge2, (unsigned char *)&auth_data);
  log_bytes("start()", "auth_data:", (char *)&auth_data, 32);

  unsigned char step4[69 + 32 + 4];
  prepare_unencrypted(CMD_AUTH_DATA, (unsigned char *)&auth_data_payload, 69, (unsigned char *)&auth_data, (unsigned char *)&step4);
  log_bytes("start()", "Step4 request:", (char *)&step4, 69 + 32 + 4);
  
  unsigned int auth_id_payload = 2;
  unsigned char auth_id_confirm[32];
  calculate_h1((unsigned char *)&shared_key, (unsigned char *)&auth_id_payload, 4, (unsigned char *)&challenge3, (unsigned char *)&auth_id_confirm);
  unsigned char step5[4 + 32 + 4];
  prepare_unencrypted(CMD_AUTH_ID_CONFIRMATION, (unsigned char *)&auth_id_payload, 4, (unsigned char *)&auth_id_confirm, (unsigned char *)&step5);
  log_bytes("start()", "Step5 request:", (char *)&step5, 4 + 32 + 4);

  unsigned char pair_key[36];
  memcpy(&pair_key, &auth_id_payload, 4);
  memcpy(&pair_key[4], &shared_key, 32);

  unsigned short keyturner_states = 0x0c;
  unsigned char read_lock_step[ENCRYPTED_BUFFER_SIZE + 2];

  prepare_encrypted((unsigned char *)&pair_key, 0x01, (unsigned char *)&keyturner_states, 2, (unsigned char *)&challenge4, (unsigned char *)&read_lock_step);
  log_bytes("start()", "Step read_lock request:", (char *)&read_lock_step, ENCRYPTED_BUFFER_SIZE + 2);

  auto msg_len1 = get_encrypted_msg_len((unsigned char *)&read_lock_step);
  auto keyturner_state = (unsigned char *)malloc(msg_len1);
  decrypt_encrypted((unsigned char *)&pair_key, (unsigned char *)&read_lock_step, (unsigned char *)keyturner_state);
  log_bytes("start()", "Step read_lock response:", (char *)keyturner_state, msg_len1);

  free(keyturner_state);

}


void on_cmd_error(unsigned char code) {
    auto outp = std::string("");
    convert_error_to_json(0, code, &outp);
    net_mqtt_publish("last_error", (char *)outp.c_str());
}

void on_bt_connection_status(bool connected, int rssi) {
    if (connected) {
        net_mqtt_publish("connection", convert_connection_status_to_json(0, connected, rssi).c_str(), true);
    } else {
        schedule_next_update(10);
    }
}

void setup() {

    Serial.begin(115200);
    preferences.begin("nuki-mqtt", false);
    // preferences.clear();

    delay(1000);
    log_init(CONFIG_VERBOSE_OUTPUT);
    Logger::notice("setup()", "Nuki MQTT is starting...");
    bt_setup(CONFIG_DEVICE_MAC, on_connected);

    read_pairing_key(&preferences, CAST_PUC &pairing_key);

    bt_set_listeners([] (unsigned char) {
        Logger::verbose("push_state()", "New state pushed");
        request_updates(&preferences, COMMAND_REQUEST_STATE);
    }, on_bt_connection_status);
    cmd_set_listeners(on_bt_state, on_cmd_error);
    net_init(CONFIG_DEVICE_MAC, "connection", "{\"connected\": false}", on_connected);
    net_set_request_listener(on_mqtt_request);
    bt_start_scan();
    Logger::notice("setup()", "Nuki MQTT started");
    schedule_next_update(15);
}

void loop() {
    bt_loop();
    net_loop();
    bool update_data_needed = millis() >= next_update;
    if (is_paired() && bt_is_found() && net_is_connected() && update_data_needed) {
        Logger::verbose("main()", "Auto-refresh data");
        request_updates(&preferences, COMMAND_REQUEST_ALL);
        if (next_update <= millis()) {
            schedule_next_update(CONFIG_REFRESH_STATE_MIN * 60);
        }
    }
}