#include <Logger.h>

#include <malloc.h>
#include <cstring>
#include <cstdio>
#include "util.h"

#define MILLIS_LEN 10
#define MODULE_LEN 25

void log_init(bool verbose) {
    Logger::setLogLevel(Logger::NOTICE);
    if (verbose) {
        Logger::setLogLevel(Logger::VERBOSE);
    }
    auto formatter = [](Logger::Level level, const char* module, const char* message) {
        auto buffer = (char *)malloc(2 + MILLIS_LEN + 9 + 3 + max((int)strlen(module), MODULE_LEN) + 1 + strlen(message));
        sprintf(buffer, "[%*lu][%7s] %-*s: %s", MILLIS_LEN, millis(), Logger::asString(level), MODULE_LEN, module, message);
        Serial.println(buffer);
        free(buffer);
    };
    Logger::setOutputFunction(formatter);
}

void log_bytes(const char *module, const char *message, char *data, int len) {
    char *hex_buffer = (char *)malloc(2 * len + 1);
    char *msg = (char *)malloc(strlen(message) + 2 + 2 * len);
    for (int i = 0; i < len; i++) {
        sprintf(&hex_buffer[2 * i], "%02x", data[i]);
    }

    sprintf(msg, "%s %s", message, hex_buffer);
    Logger::verbose(module, msg);
    
    free(hex_buffer);
    free(msg);
}

String convert_mac_id(const char *mac) {
    auto addr = String(mac);
    addr.toLowerCase();
    addr.replace(":", "");
    auto result = String("0x") + addr;
    return result;
}