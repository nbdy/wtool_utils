#include <string>
#include <iostream>

#include <args.h>
#include <ohlog.h>

#include <Sniffer.h>

int main(int argc, char** argv) {
    auto *log = ohlog::Logger::get();
    std::string LOG_TAG = "main.cpp";

    if(geteuid() != 0) {
        log->e(LOG_TAG, "Run this program as root!");
        return 0;
    }

    args::ArgumentParser p("wtool_utils");
    args::HelpFlag help(p, "help", "This help menu", {'h', "help"});
    args::ValueFlag<std::string> interface(p, "interface", "Which interface to use", {'i', "interface"}, "wlan0");
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

    Sniffer sniffer;
    sniffer.start(args::get(interface), true, true, args::get(filter));

    return 0;
}
