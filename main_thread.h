#include <thread>
#include <future>
#include <vector>
#include <memory>

#ifndef VPN_MAIN_THREAD_H
#define VPN_MAIN_THREAD_H

namespace VPN
{
    class Channel;

    class MainThread
    {
    public:
        MainThread(int listenPort);
        ~MainThread();

    public:
        void init(const std::vector<int>& sendSockFds);
        void start(std::future<void>& futureObj);
        void join();

        int getEpollFd() { return _epollFd; }
        int getSendSockFd(int index) { return _sendSockFds[index]; }
        int getListenFd() { return _listenFd; }
        int getListenPort() { return _listenPort; }
        int getSendSockFdSize() { return _sendSockFds.size(); }
        void setRunFlag(bool flag) { _runFlag = flag; }

    protected:
        void createEpollIpv4Server();
        void threadFunction(std::future<void> futureObj);
        bool isIPv4(const std::string& ipAddress);
        int setNonBlock(int fd, bool value);

    private:
        int _epollFd;
        int _listenFd; // ipv4监听套接字
        int _listenFd6; // ipv6监听套接字
        int _listenPort; // 监听端口

        std::vector<int> _sendSockFds;
        std::shared_ptr<std::thread> _thread;
        bool _runFlag;
    };
}

#endif
