//
// Created by nbdy on 22.03.21.
//

#ifndef WTOOL_UTILS_SNIFFER_H
#define WTOOL_UTILS_SNIFFER_H

#include <string>
#include <mutex>
#include <tins/tins.h>

#include <msgpack.hpp>
#include <sck.h>

// TODO(nbdy): check if we actually need msgpack, or if we can cast it to a char array and cast that back on the other side
struct WiFiPacket {
    std::string addr1;
    std::string addr2;
    std::string addr3;
    std::string addr4;
    std::string country;
    std::string challengeText;
    bool toDs = false;
    bool fromDs = false;
    std::vector<float> rates;
    std::vector<float> extendedRates;
    std::pair<uint8_t, uint8_t> powerCapability;
    std::vector<std::pair<uint8_t, uint8_t>> channels;
    uint8_t type {};

    MSGPACK_DEFINE(addr1, addr2, addr3, addr4, country, challengeText, toDs, fromDs, rates, extendedRates,
                   powerCapability, channels);
};

class Sniffer;

class PacketPipe: public nbdy::SocketContainer {
    std::mutex mtxQueue;
    std::vector<std::string> queue;

    std::mutex mtxClientConnected;
    bool clientConnected = false;

public:
    PacketPipe(): nbdy::SocketContainer() {
        create();
    }

    void setClientConnected(bool value) {
        mtxClientConnected.lock();
        clientConnected = value;
        mtxClientConnected.unlock();
    }

    bool getClientConnected() {
        mtxClientConnected.lock();
        bool r = clientConnected;
        mtxClientConnected.unlock();
        return r;
    }

    void enqueue(char* data) {
        mtxQueue.lock();
        queue.emplace_back(data);
        mtxQueue.unlock();
    }

    std::vector<std::string> getQueue() {
        mtxQueue.lock();
        std::vector<std::string> r(queue);
        queue.clear();
        mtxQueue.unlock();
        return r;
    }
};


class Sniffer {
public:
    Sniffer(): packetPipe(PacketPipe()), log(ohlog::Logger::get()){}

    void start(const std::string& interface, bool rf_mon, bool promiscuous, const std::string& filter="") {
        log->i(LOG_TAG, "Starting");
        std::thread pipeThread([this]{
            log->i(LOG_TAG, "Listening for incoming connections");
            packetPipe.listenOn(1339, [](const std::string& host, int port, int fp, void* ctx){
                ohlog::Logger::get()->i("PacketPipe", "New connection from %s:%i", host.c_str(), port);
                auto pp = (PacketPipe*) ctx;
                pp->setClientConnected(true);
                while(pp->getDoRun()) {
                    auto q = pp->getQueue();
                    if(!q.empty()) {
                        ohlog::Logger::get()->i("PacketPipe", "Sending %i packets", q.size());
                        for(const auto& o : pp->getQueue()) PacketPipe::writeTo(fp, o);
                    }
                    usleep(50000); // 50 ms
                }
            });
        });
        log->i(LOG_TAG, "Setting up sniffer");
        run(interface, rf_mon, promiscuous, filter);
    }

    void stop() {
        sniffer->stop_sniff();
        packetPipe.stop();
    }

    void run(const std::string& interface, bool rf_mon, bool promiscuous, const std::string& filter="") {
        cfg.set_promisc_mode(promiscuous);
        cfg.set_rfmon(rf_mon);
        cfg.set_filter(filter);
        sniffer = new Tins::Sniffer(interface, cfg);
        log->i(LOG_TAG, "Sniffing");
        sniffer->sniff_loop(Tins::make_sniffer_handler(this, &Sniffer::callback));
    }

    template<typename T> char* serialize(T data) {
        msgpack::sbuffer sbuf;
        msgpack::pack(sbuf, data);
        return sbuf.data();
    }

    void checkBeacon(Tins::PDU& pdu) {
        auto beacon = pdu.rfind_pdu<Tins::Dot11ManagementFrame>();
        if(!beacon.from_ds() && !beacon.to_ds()) {
            WiFiPacket wiFiPacket;
            wiFiPacket.addr1 = beacon.addr1().to_string();
            wiFiPacket.addr2 = beacon.addr2().to_string();
            wiFiPacket.addr3 = beacon.addr3().to_string();
            wiFiPacket.addr4 = beacon.addr4().to_string();
            wiFiPacket.country = beacon.country().country;
            wiFiPacket.challengeText = beacon.challenge_text();
            wiFiPacket.toDs = beacon.to_ds();
            wiFiPacket.fromDs = beacon.from_ds();
            wiFiPacket.rates = beacon.supported_rates();
            wiFiPacket.extendedRates = beacon.extended_supported_rates();
            wiFiPacket.powerCapability = beacon.power_capability();
            wiFiPacket.channels = beacon.supported_channels();
            wiFiPacket.type = beacon.pdu_type();
            log->d(LOG_TAG, "Enqueuing wifi packet\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s",
                   wiFiPacket.addr1.c_str(), wiFiPacket.addr2.c_str(),
                   wiFiPacket.addr3.c_str(), wiFiPacket.addr4.c_str(),
                   wiFiPacket.country.c_str());
            packetPipe.enqueue(serialize(wiFiPacket));
        }
    }

    bool callback(Tins::PDU& pdu) {
        // if(!packetPipe.getClientConnected()) return true;
        checkBeacon(pdu);
        return true;
    }

private:
    std::string LOG_TAG = "Sniffer";

    Tins::SnifferConfiguration cfg;
    Tins::Sniffer *sniffer = nullptr;

    ohlog::Logger *log = nullptr;
    PacketPipe packetPipe;
};

#endif //WTOOL_UTILS_SNIFFER_H
