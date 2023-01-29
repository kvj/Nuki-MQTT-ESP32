#include "store.h"
#include "util.h"
#include <Logger.h>

void read_pairing_key(Preferences *preferences, unsigned char *out) {
    out[0] = 0;  
    int len = preferences->getBytesLength(PREF_PAIRING);
    if (len == PREF_PAIRING_LEN) {
        preferences->getBytes(PREF_PAIRING, out, PREF_PAIRING_LEN);
        log_bytes("read_pairing_key()", "Pairing key from prefs:", (char *)out, PREF_PAIRING_LEN);
    }
}

void store_pairing_key(Preferences *preferences, unsigned char *out) {
    preferences->putBytes(PREF_PAIRING, out, PREF_PAIRING_LEN);
}

void read_ids_array(Preferences *preferences, const char *name, unsigned char *out, int item_size) {
    int len = preferences->getBytesLength(name);
    unsigned short size = 0;
    if (len != 0) {
        preferences->getBytes(name, out, len);
        memcpy(&size, out, 2);
        if (size * item_size + 2 == len) {
            log_bytes("read_ids_array()", "Array:", (char *)out, len);
            return;
        }
        auto log = String("Size doesn't match: ") + String(size) + " for " + String(name);
        Logger::verbose("read_ids_array()", log.c_str());
    }
    auto log = String("No IDs saved for ") + String(name);
    Logger::verbose("read_ids_array()", log.c_str());
    out[0] = 0;
    out[1] = 0;
}

void store_ids_array(Preferences *preferences, const char *name, unsigned char *in, int item_size) {
    unsigned short size = 0;
    memcpy(&size, in, 2);
    log_bytes("store_ids_array()", "Array:", (char *)in, size * item_size + 2);
    preferences->putBytes(name, in, size * item_size + 2);
}

unsigned short read_pin(Preferences *preferences) {
    return (unsigned short)preferences->getShort(PREF_PIN);
}

void store_pin(Preferences *preferences, unsigned short pin) {
    preferences->putShort(PREF_PIN, pin);
}
