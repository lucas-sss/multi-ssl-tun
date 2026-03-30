#include <iostream>

#include "fd_dispatcher.h"
#include "main_thread.h"
#include "ssl_work_thread.h"

// TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.

using namespace VPN;

std::vector<std::shared_ptr<std::promise<void>>> exitSignals;
std::vector<std::shared_ptr<VPN::MainThread>> mainThreads;
std::vector<std::shared_ptr<VPN::SslWorkThread>> sslWorkThreads;

int main()
{
    int exitSinalIndex = 0;
    int workThreadCount = 6;
    int listenPort;

    VPN::SocketPair socketPair{workThreadCount};
    socketPair.InitSocketPair();


    auto mainThread = std::make_shared<VPN::MainThread>(listenPort);
    mainThreads.push_back(mainThread);
    auto mainFeatureObj = exitSignals[exitSinalIndex++]->get_future();
    mainThread->init(socketPair.getSendFds());
    mainThread->start(mainFeatureObj);


    int cpuIndex = 0;
    for (int i = 0; i < workThreadCount; i++)
    {
        // TODO tunfd
        auto sslWorkThread = std::make_shared<VPN::SslWorkThread>(socketPair.getRecvFd(i), 0);
        sslWorkThreads.push_back(sslWorkThread);
        sslWorkThread->initThread();
        auto futureObj = exitSignals[exitSinalIndex++]->get_future();
        sslWorkThread->startThread(cpuIndex++, futureObj);
    }


    mainThread->join();
    return 0;
    // TIP See CLion help at <a href="https://www.jetbrains.com/help/clion/">jetbrains.com/help/clion/</a>. Also, you can try interactive lessons for CLion by selecting 'Help | Learn IDE Features' from the main menu.
}
