#include <Logger.h>

#include "bt_command.h"
#include "util.h"

cmd_state_change_fn state_change_listener = NULL;
cmd_error_fn error_listener = NULL;

void cmd_set_listeners(cmd_state_change_fn state_change_fn, cmd_error_fn error_fn) {
    state_change_listener = state_change_fn;
    error_listener = error_fn;
}

bool accept_first(unsigned char *in, int in_len) {
    return true;
}

bool cmd_pair(bt_read_write_fn read_write, unsigned char *out36) {
    Logger::notice("cmd_pair()", "Starting pairing");

    // unsigned char cl_public_key[32];
    // unsigned char cl_private_key[32];
    // calculate_keypair((unsigned char *)&cl_private_key, (unsigned char *)&cl_public_key);
    // log_bytes("cmd_pair()", "CL Public key:", (char *)&cl_public_key, 32);
    // log_bytes("cmd_pair()", "CL Private key:", (char *)&cl_private_key, 32);

    unsigned char out256[256];

    unsigned char step1[2 + 4];
    unsigned short step1_payload = CMD_PUBLIC_KEY;
    prepare_unencrypted(CMD_REQUEST_DATA, (unsigned char *)&step1_payload, 2, NULL, (unsigned char *)&step1);
    log_bytes("cmd_pair()", "Step1 request:", (char *)&step1, 2 + 4);
    int size = read_write((unsigned char *)&step1, 6, (unsigned char *)&out256, accept_first);
    auto err = check_error(CMD_PUBLIC_KEY, (unsigned char *)&out256, size);
    if (err != 0) {
        auto log = String("Error getting public key: 0x") + String(err, 16);
        Logger::warning("cmd_pair()", log.c_str());
        error_listener(err);
        return false;
    }
    log_bytes("cmd_pair()", "Step1 response:", (char *)&out256, size);
    unsigned char sl_public_key[32];
    extract_unencrypted((unsigned char *)&out256, (unsigned char *)&sl_public_key, 32);
    log_bytes("cmd_pair()", "SL Public key:", (char *)&sl_public_key, 32);

    const char cl_private_key[] =   "\x8C\xAA\x54\x67\x23\x07\xBF\xFD\xF5\xEA\x18\x3F\xC6\x07\x15\x8D\x20\x11\xD0\x08\xEC\xA6\xA1\x08\x86\x14\xFF\x08\x53\xA5\xAA\x07";
    const char cl_public_key[] =    "\xF8\x81\x27\xCC\xF4\x80\x23\xB5\xCB\xE9\x10\x1D\x24\xBA\xA8\xA3\x68\xDA\x94\xE8\xC2\xE3\xCD\xE2\xDE\xD2\x9C\xE9\x6A\xB5\x0C\x15";
    
    unsigned char step2[32 + 4];
    prepare_unencrypted(CMD_PUBLIC_KEY, (unsigned char *)&cl_public_key, 32, NULL, (unsigned char *)&step2);
    log_bytes("cmd_pair()", "Step2 request:", (char *)&step2, 32 + 4);

    size = read_write((unsigned char *)&step2, 36, (unsigned char *)&out256, accept_first);
    err = check_error(CMD_CHALLENGE, (unsigned char *)&out256, size);
    if (err != 0) {
        auto log = String("Error getting challenge: 0x") + String(err, 16);
        Logger::warning("cmd_pair()", log.c_str());
        error_listener(err);
        return false;
    }

    log_bytes("cmd_pair()", "Step2 response:", (char *)&out256, size);
    unsigned char sl_challenge[32];
    unsigned char cl_challenge[32];
    extract_unencrypted((unsigned char *)&out256, (unsigned char *)&sl_challenge, 32);

    unsigned char dh1[32];
    calculate_dh1((unsigned char *)&dh1, (unsigned char *)&cl_private_key, (unsigned char *)&sl_public_key);
    log_bytes("cmd_pair()", "dh1:", (char *)&dh1, 32);
    unsigned char shared_key[32];
    calculate_kdh1((unsigned char *)&dh1, (unsigned char *)&shared_key);
    log_bytes("cmd_pair()", "shared key:", (char *)&shared_key, 32);

    unsigned char keys[64];
    prepare_auth_authenticator((unsigned char *)&cl_public_key, (unsigned char *)&sl_public_key, (unsigned char *)&keys);

    unsigned char auth_auth[32];

    calculate_h1((unsigned char *)&shared_key, (unsigned char *)&keys, 64, (unsigned char *)&sl_challenge, (unsigned char *)&auth_auth);
    log_bytes("cmd_pair()", "auth_auth:", (char *)&auth_auth, 32);

    unsigned char step3[32 + 4];
    prepare_unencrypted(CMD_AUTH_AUTHENTICATOR, (unsigned char *)&auth_auth, 32, NULL, (unsigned char *)&step3);
    log_bytes("cmd_pair()", "Step3 request:", (char *)&step3, 32 + 4);

    size = read_write((unsigned char *)&step3, 36, (unsigned char *)&out256, accept_first);
    err = check_error(CMD_CHALLENGE, (unsigned char *)&out256, size);
    if (err != 0) {
        auto log = String("Error getting challenge #2: 0x") + String(err, 16);
        Logger::warning("cmd_pair()", log.c_str());
        error_listener(err);
        return false;
    }
    log_bytes("cmd_pair()", "Step3 response:", (char *)&out256, size);
    extract_unencrypted((unsigned char *)&out256, (unsigned char *)&sl_challenge, 32);
    calculate_challenge((unsigned char *)&cl_challenge, 32);

    unsigned char auth_data_payload[69];
    unsigned int id = ESP.getEfuseMac();
    prepare_auth_data(1, id, (char *)String("Nuki MQTT").c_str(), (unsigned char *)&cl_challenge, (unsigned char *)&auth_data_payload);
    log_bytes("cmd_pair()", "auth_data_payload:", (char *)&auth_data_payload, 69);

    unsigned char auth_data[32];
    calculate_h1((unsigned char *)&shared_key, (unsigned char *)&auth_data_payload, 69, (unsigned char *)&sl_challenge, (unsigned char *)&auth_data);
    log_bytes("cmd_pair()", "auth_data:", (char *)&auth_data, 32);

    unsigned char step4[69 + 32 + 4];
    prepare_unencrypted(CMD_AUTH_DATA, (unsigned char *)&auth_data_payload, 69, (unsigned char *)&auth_data, (unsigned char *)&step4);
    log_bytes("cmd_pair()", "Step4 request:", (char *)&step4, 69 + 32 + 4);

    size = read_write((unsigned char *)&step4, 69 + 32 + 4, (unsigned char *)&out256, accept_first);
    err = check_error(CMD_AUTH_ID, (unsigned char *)&out256, size);
    if (err != 0) {
        auto log = String("Error getting authorization ID: 0x") + String(err, 16);
        Logger::warning("cmd_pair()", log.c_str());
        error_listener(err);
        return false;
    }
    log_bytes("cmd_pair()", "Step4 response:", (char *)&out256, size);
    
    unsigned char auth_id_response[32 + 4 + 16 + 32];
    extract_unencrypted((unsigned char *)&out256, (unsigned char *)&auth_id_response, 32 + 4 + 16 + 32);

    unsigned int auth_id;
    memcpy(&auth_id, &auth_id_response[32], 4);
    memcpy(&sl_challenge, &auth_id_response[32 + 4 + 16], 32);

    unsigned char auth_id_confirmation[32];
    calculate_h1((unsigned char *)&shared_key, (unsigned char *)&auth_id, 4, (unsigned char *)&sl_challenge, (unsigned char *)&auth_id_confirmation);
    log_bytes("cmd_pair()", "auth_id_confirmation:", (char *)&auth_id_confirmation, 32);

    unsigned char step5[4 + 32 + 4];
    prepare_unencrypted(CMD_AUTH_ID_CONFIRMATION, (unsigned char *)&auth_id, 4, (unsigned char *)&auth_id_confirmation, (unsigned char *)&step5);
    log_bytes("cmd_pair()", "Step5 request:", (char *)&step5, 4 + 32 + 4);

    size = read_write((unsigned char *)&step5, 4 + 32 + 4, (unsigned char *)&out256, accept_first);
    err = check_error(CMD_STATUS, (unsigned char *)&out256, size);
    if (err != 0) {
        auto log = String("Error getting pairing confirmation: 0x") + String(err, 16);
        Logger::warning("cmd_pair()", log.c_str());
        error_listener(err);
        return false;
    }
    log_bytes("cmd_pair()", "Step5 response:", (char *)&out256, size);

    memcpy(out36, &auth_id, 4);
    memcpy(&out36[4], &shared_key, 32);

    log_bytes("cmd_pair()", "Pairing key:", (char *)out36, 36);

    Logger::notice("cmd_pair()", "Pairing done");

    delay(1000);

    return true;
}

bt_accept_fn make_accept_decrypted(unsigned char *key36, unsigned char *prefix, int prefix_len) {
    // log_bytes("make_accept_decrypted()", "Pair key:", (char *)key36, 36);
    return [=](unsigned char *in, int in_len) -> bool {
        // log_bytes("make_accept_decrypted()", "Pair key (lambda):", (char *)key36, 36);
        unsigned char out256[256];
        int len = decrypt_maybe(key36, in, in_len, (unsigned char *)&out256);
        log_bytes("make_accept_decrypted()", "Decrypted:", (char *)&out256, len);
        unsigned short cmd;
        memcpy(&cmd, out256, 2);
        auto log = String("Cmd: 0x") + String(cmd, 16);
        Logger::verbose("make_accept_decrypted()", log.c_str());
        if (cmd == CMD_STATE) {
            Logger::verbose("make_accept_decrypted()", "Report state");
            if (state_change_listener)
                state_change_listener(&out256[2], len - 4);
        }
        if (cmd == CMD_ERROR_REPORT) {
            return true;
        }
        log_bytes("make_accept_decrypted()", "Comparing with:", (char *)prefix, prefix_len);
        if (memcmp(prefix, &out256, prefix_len) == 0) {
            Logger::verbose("make_accept_decrypted()", "Expected command");
            return true;
        }
        return false;
    };
}

bt_accept_fn make_accept_decrypted_short(unsigned char *key36, unsigned short prefix) {
    return make_accept_decrypted(key36, (unsigned char *)&prefix, 2);
}


bool cmd_request_state(bt_read_write_fn read_write, unsigned char *key36) {
    Logger::notice("cmd_request_state()", "Requesting device state");
    unsigned char out256[256];
    unsigned short keyturner_states = 0x0c;
    unsigned char read_lock_step[ENCRYPTED_BUFFER_SIZE + 2];
    unsigned char challenge[24];
    calculate_challenge((unsigned char *)&challenge, 24);
    prepare_encrypted(key36, CMD_REQUEST_DATA, (unsigned char *)&keyturner_states, 2, (unsigned char *)&challenge, (unsigned char *)&read_lock_step);
    log_bytes("cmd_request_state()", "Step request state request:", (char *)&read_lock_step, ENCRYPTED_BUFFER_SIZE + 2);

    const char prefix[] = "\x0c\x00";
    int size = read_write((unsigned char *)&read_lock_step, ENCRYPTED_BUFFER_SIZE + 2, (unsigned char *)&out256, make_accept_decrypted(key36, (unsigned char *)&prefix, 2));
    size = decrypt_maybe(key36, (unsigned char *)&out256, size, (unsigned char *)&out256);
    auto err = check_error(CMD_STATE, (unsigned char *)&out256, size);
    if (err != 0) {
        auto log = String("Error requesting state: 0x") + String(err, 16);
        Logger::warning("cmd_request_state()", log.c_str());
        error_listener(err);
        return false;
    }
    log_bytes("cmd_request_state()", "Encrypted:", (char *)&out256, size);
    return true;
}

bool request_challenge(bt_read_write_fn read_write, unsigned char *key36, unsigned char *out32) {
    unsigned char out256[256];

    unsigned short request_challenge = CMD_CHALLENGE;
    unsigned char challenge_step[ENCRYPTED_BUFFER_SIZE + 2];
    unsigned char challenge[24];
    calculate_challenge((unsigned char *)&challenge, 24);
    prepare_encrypted(key36, CMD_REQUEST_DATA, (unsigned char *)&request_challenge, 2, (unsigned char *)&challenge, (unsigned char *)&challenge_step);
    // log_bytes("request_challenge()", "Step request challenge:", (char *)&challenge_step, ENCRYPTED_BUFFER_SIZE + 2);

    const char prefix[] = "\x04\x00";

    int size = read_write((unsigned char *)&challenge_step, ENCRYPTED_BUFFER_SIZE + 2, (unsigned char *)&out256, make_accept_decrypted(key36, (unsigned char *)&prefix, 2));
    size = decrypt_maybe(key36, (unsigned char *)&out256, size, (unsigned char *)&out256);
    auto err = check_error(CMD_CHALLENGE, (unsigned char *)&out256, size);
    if (err != 0) {
        auto log = String("Error requesting challenge: 0x") + String(err, 16);
        Logger::warning("request_challenge()", log.c_str());
        error_listener(err);
        return false;
    }
    // log_bytes("request_challenge()", "Step response challenge:", (char *)&out256, size);
    unsigned char sl_challenge[32];
    extract_unencrypted((unsigned char *)&out256, out32, 32);
    // log_bytes("request_challenge()", "Received challenge:", (char *)&sl_challenge, 32);
    return true;
}

bool cmd_lock_action(bt_read_write_fn read_write, unsigned char *key36, unsigned char action) {
    auto log = String("Performing lock action: 0x") + String(action, 16);
    Logger::notice("cmd_lock_action()", log.c_str());

    unsigned char out256[256];
    unsigned char challenge[24];

    unsigned char sl_challenge[32];
    if (!request_challenge(read_write, key36, (unsigned char *)&sl_challenge)) {
        return false;
    }
    log_bytes("cmd_lock_action()", "Received challenge:", (char *)&sl_challenge, 32);

    unsigned char lock_action_step[ENCRYPTED_BUFFER_SIZE + 6 + 32];
    unsigned char lock_action[6 + 32];
    lock_action[0] = action;
    memset(&lock_action[1], 0, 4);
    lock_action[5] = 0;
    memcpy(&lock_action[6], &sl_challenge, 32);
    calculate_challenge((unsigned char *)&challenge, 24);
    prepare_encrypted(key36, CMD_LOCK_ACTION, (unsigned char *)&lock_action, 6 + 32, (unsigned char *)&challenge, (unsigned char *)&lock_action_step);
    log_bytes("cmd_lock_action()", "Step lock action:", (char *)&lock_action_step, ENCRYPTED_BUFFER_SIZE + 6 + 32);
    const char prefix[] = "\x0e\x00\x00"; // Status COMPLETE
    int size = read_write((unsigned char *)&lock_action_step, ENCRYPTED_BUFFER_SIZE + 6 + 32, (unsigned char *)&out256, make_accept_decrypted(key36, (unsigned char *)&prefix, 3));
    size = decrypt_maybe(key36, (unsigned char *)&out256, size, (unsigned char *)&out256);
    int err = check_error(CMD_STATUS, (unsigned char *)&out256, size);
    if (err != 0) {
        auto log = String("Error requesting state: 0x") + String(err, 16);
        Logger::warning("cmd_lock_action()", log.c_str());
        error_listener(err);
        return false;
    }
    log_bytes("cmd_lock_action()", "Step response lock action:", (char *)&out256, size);
    return true;
}

bool cmd_request_config(bt_read_write_fn read_write, unsigned char *key36, unsigned char *out256) {
    unsigned char sl_challenge[32];
    if (!request_challenge(read_write, key36, (unsigned char *)&sl_challenge)) {
        return false;
    }
    unsigned char challenge[24];
    calculate_challenge((unsigned char *)&challenge, 24);

    unsigned char request[ENCRYPTED_BUFFER_SIZE + 32];
    prepare_encrypted(key36, CMD_REQUEST_CONFIG, (unsigned char *)&sl_challenge, 32, (unsigned char *)&challenge, (unsigned char *)&request);
    const char prefix[] = "\x15\x00";
    int size = read_write((unsigned char *)&request, ENCRYPTED_BUFFER_SIZE + 32, out256, make_accept_decrypted(key36, (unsigned char *)&prefix, 2));
    size = decrypt_maybe(key36, out256, size, out256);
    auto err = check_error(CMD_CONFIG, out256, size);
    if (err != 0) {
        auto log = String("Error requesting config: 0x") + String(err, 16);
        Logger::warning("cmd_request_config()", log.c_str());
        error_listener(err);
        return false;
    }
    log_bytes("cmd_request_config()", "Response:", (char *)out256, size);
    return true;
}

bool update_pin_cmd(bt_read_write_fn read_write, unsigned char *key36, unsigned short pin, unsigned char *in, int len, unsigned short cmd) {
    unsigned char sl_challenge[32];
    if (!request_challenge(read_write, key36, CAST_PUC &sl_challenge)) {
        return false;
    }
    unsigned char challenge[24];
    calculate_challenge(CAST_PUC &challenge, 24);
    auto buffer = CAST_PUC malloc(34 + len);
    auto buffer_request = CAST_PUC malloc(ENCRYPTED_BUFFER_SIZE + 34 + len);
    memcpy(buffer, in, len);
    memcpy(&buffer[len], &sl_challenge, 32);
    memcpy(&buffer[len + 32], &pin, 2);
    log_bytes("update_pin_cmd()", "Request:", (char *)buffer, 34 + len);
    prepare_encrypted(key36, cmd, buffer, 34 + len, CAST_PUC &challenge, buffer_request);
    free(buffer);

    unsigned char out256[256];
    unsigned short status = CMD_STATUS;
    int size = read_write(buffer_request, ENCRYPTED_BUFFER_SIZE + 34 + len, CAST_PUC &out256, make_accept_decrypted(key36, CAST_PUC &status, 2));
    free(buffer_request);
    size = decrypt_maybe(key36, CAST_PUC &out256, size, CAST_PUC &out256);
    auto err = check_error(CMD_STATUS, CAST_PUC &out256, size);
    if (err != 0) {
        auto log = String("Error: 0x") + String(err, 16);
        Logger::warning("update_pin_cmd()", log.c_str());
        error_listener(err);
        return false;
    }
    return true;
}

bool cmd_update_keypad_code(bt_read_write_fn read_write, unsigned char *key36, unsigned short pin, unsigned char *in, int size) {
    return update_pin_cmd(read_write, key36, pin, in, size, CMD_UPDATE_KEYPAD_CODE);
}

bool cmd_save_config(bt_read_write_fn read_write, unsigned char *key36, unsigned short pin, unsigned char *in, int size) {
    return update_pin_cmd(read_write, key36, pin, in, size, CMD_SET_CONFIG);
}

bool request_list(bt_read_write_fn read_write, unsigned char *key36, unsigned short pin, cmd_item_fn item_fn, 
            unsigned char *in, int in_len, unsigned short cmd, unsigned short cmd_item, unsigned short cmd_count) {

    unsigned char sl_challenge[32];
    if (!request_challenge(read_write, key36, CAST_PUC &sl_challenge)) {
        return false;
    }

    unsigned char *payload_request = CAST_PUC malloc(ENCRYPTED_BUFFER_SIZE + 34 + in_len);
    unsigned char *payload = CAST_PUC malloc(34 + in_len);

    memcpy(payload, in, in_len);
    memcpy(&payload[in_len], &sl_challenge, 32);
    memcpy(&payload[in_len + 32], &pin, 2);

    unsigned char challenge[24];
    calculate_challenge((unsigned char *)&challenge, 24);

    prepare_encrypted(key36, cmd, payload, 34 + in_len, CAST_PUC &challenge, payload_request);
    auto callback = [=, &item_fn](unsigned char *in, int len) -> bool {
        unsigned char out[256];
        auto size = decrypt_maybe(key36, in, len, (unsigned char *)&out);
        unsigned short cmd;
        memcpy(&cmd, &out, 2);
        auto log = String("Cmd: 0x") + String(cmd, 16);
        Logger::verbose("request_list()", log.c_str());
        if (cmd == cmd_count) {
            log_bytes("request_list()", "Count:", (char *)&out[2], size);
            return false;
        } else if (cmd == cmd_item) {
            item_fn(&out[2]);
            return false;
        } else if (cmd == CMD_ERROR_REPORT) {
            return true;
        } else if (cmd == CMD_STATUS) {
            return true;
        }
        return false;
    };
    unsigned char out256[256];
    int size = read_write(payload_request, ENCRYPTED_BUFFER_SIZE + 34 + in_len, CAST_PUC &out256, callback);
    free(payload);
    free(payload_request);
    size = decrypt_maybe(key36, (unsigned char *)&out256, size, (unsigned char *)&out256);
    auto err = check_error(CMD_STATUS, (unsigned char *)&out256, size);
    if (err != 0) {
        auto log = String("Error requesting list: 0x") + String(err, 16);
        Logger::warning("request_list()", log.c_str());
        error_listener(err);
        return false;
    }
    return true;
}

bool cmd_request_authorizations(bt_read_write_fn read_write, unsigned char *key36, unsigned short pin, cmd_item_fn item_fn) {
    unsigned char payload[4];
    unsigned short offset = 0;
    unsigned short count = 65535;
    memcpy(&payload, &offset, 2);
    memcpy(&payload[2], &count, 2);
    return request_list(read_write, key36, pin, item_fn, CAST_PUC &payload, 4, CMD_REQUEST_AUTHORIZATIONS, CMD_AUTHORIZATION, CMD_AUTHORIZATIONS_COUNT);
}

bool cmd_request_keypad_codes(bt_read_write_fn read_write, unsigned char *key36, unsigned short pin, cmd_item_fn item_fn) {
    unsigned char payload[4];
    unsigned short offset = 0;
    unsigned short count = 65535;
    memcpy(&payload, &offset, 2);
    memcpy(&payload[2], &count, 2);
    return request_list(read_write, key36, pin, item_fn, CAST_PUC &payload, 4, CMD_REQUEST_KEYPAD_CODES, CMD_KEYPAD_CODE, CMD_KEYPAD_CODE_COUNT);
    // 4500010087d60500456e74727920636f64650000000000000000000001e50707180b1c06e5070814052518070000000000000000000000000000000000000000003077
}

bool cmd_request_log(bt_read_write_fn read_write, unsigned char *key36, unsigned short pin, cmd_item_fn item_fn) {
    unsigned char payload[8];
    unsigned int offset = 0;
    unsigned short count = 10;
    memcpy(&payload, &offset, 4);
    memcpy(&payload[4], &count, 2);
    payload[6] = 1; // desc
    payload[7] = 0;
    return request_list(read_write, key36, pin, item_fn, CAST_PUC &payload, 8, CMD_REQUEST_LOG_ENTRIES, CMD_LOG_ENTRY, CMD_LOG_ENTRIES_COUNT);
}
