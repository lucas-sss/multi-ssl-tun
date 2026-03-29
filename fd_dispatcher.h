#pragma once
#include <vector>
#include <string>
#include <string.h>

#ifndef FD_DISPATCHER_H
#define FD_DISPATCHER_H

namespace VPN
{
    struct FdDispatchMsg
    {
        bool _isIPv6; // 记录是否是IPv6连接
        int _fd; // 客户端连接fd
        int _port; // 客户端连接端口
        int _family; // 客户端连接地址族
        char _ip[64] = {0}; // 客户端连接地址

        FdDispatchMsg() = default;

        FdDispatchMsg(bool isIPv6, int fd, int port, int family, const std::string& ip)
        {
            _isIPv6 = isIPv6;
            _fd = fd;
            _port = port;
            _family = family;
            strcpy(_ip, ip.c_str());
        }

        void Init(bool isIPv6, int fd, int port, int family, const std::string& ip)
        {
            _isIPv6 = isIPv6;
            _fd = fd;
            _port = port;
            _family = family;
            strcpy(_ip, ip.c_str());
        }
    };

    class SocketPair
    {
    public:
        SocketPair(int count);
        int InitSocketPair();
        std::vector<int> getSendFds() { return _sendFds; }
        std::vector<int> getRecvFds() { return _recvFds; }
        int getSendFd(int index);
        int getRecvFd(int index);
        static int sendDispatchMsg(int fd, const struct FdDispatchMsg& msg);
        static int recvDispatchMsg(int fd, struct FdDispatchMsg* msg);
        int getSocketPairCount();
        ~SocketPair();

    private:
        int _count;
        std::vector<int> _sendFds;
        std::vector<int> _recvFds;
    };
}
#endif
