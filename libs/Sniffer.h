//
// Created by nbdy on 22.03.21.
//

#ifndef WTOOL_UTILS_SNIFFER_H
#define WTOOL_UTILS_SNIFFER_H

#include <string>
#include <mutex>
#include <tins/tins.h>
#include <sck.h>


typedef char tMAC[18];
typedef char tSSID[34];
typedef std::vector<float> tRates;
typedef char tData[256];

// TODO(nbdy): check if we actually need msgpack, or if we can cast it to a char array and cast that back on the other side
struct WiFiFrame {
    tMAC addr1 {};
    tMAC addr2 {};
    tMAC addr3 {};
    tMAC addr4 {};
    tSSID essid {};
    bool toDs = false;
    bool fromDs = false;
    tRates rates;
    uint8_t type {};
};

class Sniffer;

class PacketPipe: public nbdy::SocketContainer {
    std::mutex mtxQueue;
    std::vector<char*> queue;

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

    std::vector<char*> getQueue() {
        mtxQueue.lock();
        std::vector<char*> r(queue);
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
                while(pp->getDoRun() && pp->getClientConnected()) {
                    auto q = pp->getQueue();
                    if(!q.empty()) {
                        ohlog::Logger::get()->i("PacketPipe", "Sending %i packets", q.size());
                        for(char* o : pp->getQueue()) {
                            ohlog::Logger::get()->i("PacketPipe", "Sending: %s\n", o);
                            PacketPipe::writeTo(fp, o, sizeof(WiFiFrame));
                        }
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

    void join() {

    }

    void run(const std::string& interface, bool rf_mon, bool promiscuous, const std::string& filter="") {
        cfg.set_promisc_mode(promiscuous);
        cfg.set_rfmon(rf_mon);
        cfg.set_filter(filter);
        sniffer = new Tins::Sniffer(interface, cfg);
        log->i(LOG_TAG, "Sniffing");
        sniffer->sniff_loop(Tins::make_sniffer_handler(this, &Sniffer::callback));
    }

    void checkManagementFrame(Tins::PDU& pdu) {
        auto managementFrame = pdu.rfind_pdu<Tins::Dot11ManagementFrame>();

        auto* frame = new WiFiFrame;
        memcpy(frame->addr1, managementFrame.addr1().to_string().c_str(), sizeof(tMAC));
        memcpy(frame->addr2, managementFrame.addr2().to_string().c_str(), sizeof(tMAC));
        memcpy(frame->addr3, managementFrame.addr3().to_string().c_str(), sizeof(tMAC));
        memcpy(frame->addr4, managementFrame.addr4().to_string().c_str(), sizeof(tMAC));
        try {
            frame->toDs = managementFrame.to_ds();
            frame->fromDs = managementFrame.from_ds();
            frame->rates = managementFrame.supported_rates();
            frame->type = managementFrame.pdu_type();
        } catch (Tins::option_not_found &e) {}

        if(!managementFrame.from_ds() && !managementFrame.to_ds()) {
            auto beacon = pdu.rfind_pdu<Tins::Dot11Beacon>();
            memcpy(frame->essid, beacon.ssid().c_str(), sizeof(tSSID));
        }

        log->d(LOG_TAG, "Enqueuing wifi packet\n\t%s\n\t%s\n\t%s\n\t%s\n\tESSID: %s\n",
               frame->addr1, frame->addr2, frame->addr3, frame->addr4, frame->essid);
        packetPipe.enqueue((char*) frame);
        delete frame;
    }

    bool callback(Tins::PDU& pdu) {
        if(!packetPipe.getClientConnected()) return true;
        checkManagementFrame(pdu);
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
