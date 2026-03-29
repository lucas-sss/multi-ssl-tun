#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <poll.h>
#include <sys/epoll.h>

#include <netinet/tcp.h>
#include <iostream>

#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <chrono>


#include "main_thread.h"
#include "fd_dispatcher.h"
#include "logger.h"

namespace VPN
{
    MainThread::MainThread(int listenPort)
    {
        _listenPort = listenPort;
        _runFlag = true;
    }

    void MainThread::init(const std::vector<int>& sendSockFds)
    {
        LOG_DEBUG("MainThread::%s sendSockFds size:%d\n", __FUNCTION__, sendSockFds.size());
        _sendSockFds = sendSockFds;
        for (int fd : _sendSockFds)
        {
            LOG_INFO("MainThread send fd: %d\n", fd);
        }
        createEpollIpv4Server();
    }

    void MainThread::start(std::future<void>& futureObj)
    {
        LOG_DEBUG("MainThread::%s\n", __FUNCTION__);
        _thread = std::make_shared<std::thread>(&MainThread::threadFunction, this, std::move(futureObj));
    }

    void MainThread::threadFunction(std::future<void> futureObj)
    {
        const int kMaxEvents = 1024; // 10240
        struct epoll_event activeEvs[kMaxEvents];
        int epollFd = getEpollFd();
        int serverFd = getListenFd();
        int sendFdsSize = getSendSockFdSize();
        LOG_DEBUG("main thread running...., epollFd: %d, server fd: %d\n", epollFd, serverFd);
        while (futureObj.wait_for(std::chrono::nanoseconds(10)) == std::future_status::timeout && _runFlag)
        {
            int n = epoll_wait(epollFd, activeEvs, kMaxEvents, 100);
            for (int i = n - 1; i >= 0; i--)
            {
                if (activeEvs[i].data.fd == serverFd)
                {
                    struct sockaddr_in raddr;
                    socklen_t rsz = sizeof(raddr);
                    int cfd;
                    cfd = accept4(serverFd, (struct sockaddr*)&raddr, &rsz, SOCK_CLOEXEC);
                    if (cfd != -1)
                    {
                        int index = cfd % sendFdsSize;
                        LOG_INFO("客户端连接(ipv4) (index: %d) (from %s:%d)\n", index, inet_ntoa(raddr.sin_addr),
                                 ntohs(raddr.sin_port));
                        FdDispatchMsg msg{
                            false, cfd, ntohs(raddr.sin_port), raddr.sin_family, inet_ntoa(raddr.sin_addr)
                        };
                        SocketPair::sendDispatchMsg(getSendSockFd(index), msg);
                        LOG_INFO("客户端连接cFd: %d, 发送到业务线程(%d)连接Fd: %d\n", cfd, index, getSendSockFd(index));
                    }
                }
            }
        }
        LOG_DEBUG("Main thread : %ld end.....\n", _thread->get_id());
    }

    bool MainThread::isIPv4(const std::string& ipAddress)
    {
        struct sockaddr_in sa;
        if (inet_pton(AF_INET, ipAddress.c_str(), &(sa.sin_addr)) != 1)
        {
            return false;
        }
        else
        {
            return true;
        }
    }

    int MainThread::setNonBlock(int fd, bool value)
    {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0)
        {
            return errno;
        }
        if (value)
        {
            return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }
        return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    }

    void MainThread::join()
    {
        if (_thread && _thread->joinable())
        {
            _thread->join();
        }
    }

    MainThread::~MainThread()
    {
        if (_epollFd > 0)
        {
            ::close(_epollFd);
        }
    }

    void MainThread::createEpollIpv4Server()
    {
        // 创建监听socket
        _listenFd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (_listenFd < 0)
        {
            LOG_ERROR("socket failed\n");
            return;
        }
        // 设置监听socket为非阻塞
        int flags = fcntl(_listenFd, F_GETFL, 0);
        fcntl(_listenFd, F_SETFL, flags | O_NONBLOCK);
        // 设置端口复用
        int on = 1;
        setsockopt(_listenFd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        setsockopt(_listenFd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
        // 绑定端口
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(_listenPort);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        // 绑定
        if (bind(_listenFd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        {
            LOG_ERROR("bind failed\n");
            return;
        }
        // 监听
        if (listen(_listenFd, 100) < 0)
        {
            LOG_ERROR("listen failed\n");
            return;
        }
        // 创建epoll实例
        _epollFd = epoll_create1(EPOLL_CLOEXEC);
        if (_epollFd < 0)
        {
            LOG_ERROR("epoll_create1 failed\n");
            return;
        }
        struct epoll_event event;
        // event.events = EPOLLIN | EPOLLET; // 边缘触发
        event.events = EPOLLIN; // 水平触发
        event.data.fd = _listenFd;
        if (epoll_ctl(_epollFd, EPOLL_CTL_ADD, _listenFd, &event) < 0)
        {
            LOG_ERROR("epoll_ctl failed\n");
            return;
        }
        LOG_INFO("%s 监听端口: %d, listenfd: %d\n", __FUNCTION__, _listenPort, _listenFd);
    }
}
