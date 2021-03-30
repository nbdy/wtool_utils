#include <string>
#include <iostream>
#include <csignal>

#include <args.h>
#include <ohlog.h>

#include <Sniffer.h>

Sniffer *sniffer = nullptr;

void signal_handler(int) {
    if(sniffer != nullptr) {
        sniffer->stop();
        sniffer->join();
        delete sniffer;
    }
}

int main(int argc, char** argv) {
    auto *log = ohlog::Logger::get();
    std::string LOG_TAG = "main.cpp";

    if(geteuid() != 0) {
        log->e(LOG_TAG, "Run this program as root!");
        return 0;
    }

    signal(SIGINT, signal_handler);

    args::ArgumentParser p("wtool_utils");
    args::HelpFlag help(p, "help", "This help menu", {'h', "help"});
    args::ValueFlag<std::string> interface(p, "interface", "Which interface to use", {'i', "interface"}, "wlx00c0caabaadc");
    args::ValueFlag<std::string> filter(p, "extra pcap filter", "Extra pcap filter for the sniffer", {"pf", "pcap-filter"}, "type mgt");
    try {
        p.ParseCLI(argc, argv);
    } catch(args::Help&) {
        std::cout << p;
        return 0;
    } catch(args::ParseError& e) {
        log->e(LOG_TAG, e.what());
        std::cerr << p;
        return 1;
    } catch(args::ValidationError& e) {
        log->e(LOG_TAG, e.what());
        std::cerr << p;
        return 1;
    }

    sniffer = new Sniffer();
    sniffer->start(args::get(interface), true, true, args::get(filter));

    return 0;
}
