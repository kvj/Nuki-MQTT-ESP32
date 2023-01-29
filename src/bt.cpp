#include "bt.h"
#include "util.h"
#include <Logger.h>

bt_state_push_fn state_push_listener = NULL;
bt_connection_status_fn connection_status_listener;
bt_connected_fn bt_connected_listener = NULL;


static NimBLEAddress scan_address;

static NimBLEUUID pairService = NimBLEUUID("a92ee100-5501-11e4-916c-0800200c9a66");
static NimBLEUUID pairCharacteristic = NimBLEUUID("a92ee101-5501-11e4-916c-0800200c9a66");
static NimBLEUUID serviceService = NimBLEUUID("a92ee200-5501-11e4-916c-0800200c9a66");
static NimBLEUUID serviceGDIOCharacteristic = NimBLEUUID("a92ee201-5501-11e4-916c-0800200c9a66");
static NimBLEUUID serviceUSDIOCharacteristic = NimBLEUUID("a92ee202-5501-11e4-916c-0800200c9a66");

bool device_found = false;
unsigned char tx_power_pending = 0;
bool connected_pending = false;

bool bt_is_found() {
    return device_found;
}

class AdvertisedDeviceCallbacks: public NimBLEAdvertisedDeviceCallbacks {
    void onResult(NimBLEAdvertisedDevice* advertisedDevice) {
        if (advertisedDevice->getAddress() == scan_address) {
            if (!device_found) {
                auto log = std::string("Device found: ");
                log += advertisedDevice->getAddress().toString();
                Logger::verbose("bt_scan()", log.c_str());
                device_found = true;
                connected_pending = true;
            }
            if (advertisedDevice->haveManufacturerData()) {
                auto data = advertisedDevice->getManufacturerData();

                // log_bytes("bt_scan()", "Manufacturer data:", (char *)data.data(), data.length());

                // 4c000215a92ee200550111e4916c0800200c9a6628f60134c5
                if (data.length() >= 25) {
                    auto tx_power = data.data()[24];
                    if ((tx_power & 1) != 0) {
                        auto log = String("TxPower: 0x") + String(tx_power, 16);
                        Logger::verbose("bt_scan()", log.c_str());
                        tx_power_pending = tx_power;
                    }
                }
            }
        }
    }
};

void scanEndedCB(NimBLEScanResults results) {
    Logger::verbose("bt()", "Scan ended");
}


void bt_start_scan() {
    NimBLEScan* pScan = NimBLEDevice::getScan();
    pScan->setAdvertisedDeviceCallbacks(new AdvertisedDeviceCallbacks());

    pScan->setInterval(40);
    pScan->setWindow(40);
    pScan->setDuplicateFilter(false);
    pScan->setMaxResults(0);

    pScan->setActiveScan(false);
    pScan->start(0, scanEndedCB);
    Logger::verbose("bt()", "Scan started");

}

NimBLEClient* bt_connect() {
    NimBLEClient* pClient = NULL;

    if(NimBLEDevice::getClientListSize()) {
        pClient = NimBLEDevice::getClientByPeerAddress(scan_address);
        if (pClient) {
            Logger::verbose("bt_connect()", "Already know the device");
            if (!pClient->connect(scan_address, false)) {
                Logger::error("bt_connect()", "Failed to reconnect");
                return NULL;
            }
        } else {
            pClient = NimBLEDevice::getDisconnectedClient();
        }
    }

    if (!pClient) {
        pClient = NimBLEDevice::createClient();

        pClient->setConnectionParams(12,12,0,101);
        pClient->setConnectTimeout(1);

        if (!pClient->connect(scan_address)) {
            Logger::error("bt_connect()", "Failed to connect");
            NimBLEDevice::deleteClient(pClient);
            return NULL;
        }
    }

    if (!pClient->isConnected()) {
        if (!pClient->connect(scan_address)) {
            Logger::error("bt_connect()", "Failed to connect");
            return NULL;
        }
    }

    auto log = String("Connected to device, RSSI: ") + String(pClient->getRssi());
    Logger::verbose("bt_connect()", log.c_str());

    return pClient;
}

NimBLERemoteCharacteristic* bt_find_characteristic(NimBLEClient *client, const NimBLEUUID service, const NimBLEUUID characteristic) {
    NimBLERemoteService* pSvc = client->getService(service);
    if (pSvc) {
        NimBLERemoteCharacteristic* pChr = pSvc->getCharacteristic(characteristic);
        if (pChr) {
            return pChr;
        } else {
            Logger::error("Char not found");
        }
    } else {
        Logger::error("Service not found");
    }
    return NULL;
}

bool bt_run(int service, bt_connect_fn on_connect, int retries) {
    NimBLEDevice::getScan()->stop();
    delay(10);
    Logger::verbose("bt_run()", "Connecting...");
    NimBLEClient *client = NULL;
    for (int i = 0; i < retries; i++) {
        auto _client = bt_connect();
        if (_client) {
            client = _client;
            break;
        }
        delay(100);
        Logger::notice("bt_run()", "Connection attempt failed, retrying...");
    }
    bool result = false;
    if (client) {
        connection_status_listener(true, client->getRssi());
        NimBLERemoteCharacteristic *chr;
        NimBLERemoteCharacteristic *extra_chr = NULL;
        switch (service) {
            case SERVICE_GDIO:
                chr = bt_find_characteristic(client, pairService, pairCharacteristic);
                break;
            case SERVICE_USDIO:
                chr = bt_find_characteristic(client, serviceService, serviceUSDIOCharacteristic);
                extra_chr = bt_find_characteristic(client, serviceService, serviceGDIOCharacteristic);
                break;
        }
        if (chr && chr->canIndicate() && chr->canWrite()) {
            auto fn = [&chr, &client, &extra_chr](unsigned char *in, int in_len, unsigned char *out256, bt_accept_fn accept_fn) -> int {
                int result_len = -1;
                auto indication = [&result_len, &out256, &accept_fn](NimBLERemoteCharacteristic* chr, uint8_t* pData, size_t length, bool isNotify) {
                    log_bytes("bt()", "Indication:", (char *)pData, length);
                    if (accept_fn((unsigned char *)pData, length)) {
                        memcpy(out256, pData, length);
                        result_len = length;
                    }
                };
                Logger::verbose("bt_run()", "Writing data");
                chr->subscribe(false, indication);
                if (extra_chr) {
                    extra_chr->subscribe(false, indication);
                }
                bool write_result = chr->writeValue(in, in_len, true);
                auto log = String("Writing result: ") + String(write_result);
                Logger::verbose("bt_run()", log.c_str());
                while (result_len == -1 && client->isConnected()) {
                    delay(1);
                }
                chr->unsubscribe();
                Logger::verbose("bt_run()", "Read-write done");
                return result_len;
            };
            on_connect(fn);
            result = true;
        } else {
            Logger::warning("bt_run()", "Invalid Characteristic");
            connection_status_listener(false, 0);
            result = false;
        }
        Logger::verbose("bt_run()", "Disconnecting");
        client->disconnect();
        delay(10);
    } else {
        Logger::warning("bt_run()", "Failed to connect");
        connection_status_listener(false, 0);
        result = false;
    }
    bt_start_scan();
    return result;
}

void bt_setup(const char *device_address, bt_connected_fn connected_fn) {
    bt_connected_listener = connected_fn;
    NimBLEDevice::init("");

    scan_address = NimBLEAddress(device_address);

    std::string log = "Device address: ";
    log += scan_address.toString();
    Logger::verbose("bt()", log.c_str());

}

void bt_loop() {
    if (tx_power_pending) {
        if (state_push_listener) {
            state_push_listener(tx_power_pending);
        }
        tx_power_pending = 0;
        connected_pending = false; // Avoid two listeners
    }
    if (connected_pending) {
        bt_connected_listener();
        connection_status_listener(false, 0);
        connected_pending = false; // Avoid two listeners
    }
}

void bt_set_listeners(bt_state_push_fn state_push_fn, bt_connection_status_fn connection_status_fn) {
    state_push_listener = state_push_fn;
    connection_status_listener = connection_status_fn;
}