#include <iostream>
#include <set>
#include <mutex>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include "logger.h"
#include "tcpProxy.h"
#include "global.h"


#ifndef VPN_ChANNEL_H
#define VPN_ChANNEL_H

namespace VPN
{
    static const int MAX_BUF_LEN = 20480;
    static const int MTU = 1500;

    struct Channel
    {
        int fd_; // 客户端连接fd
        int tfd_; // 虚拟网卡tunfd
        int epollfd_; // epoll fd
        int events_; // 记录epoll事件
        int accept_fd_; // 判断是否进入第三步(accept)
        char vip_[64]; // 分配的客户端虚拟IP地址

        SSL* ssl_; // 安全连接ssl
        std::mutex mutex_; // 互斥锁

        bool isDeleted_; // 是否删除标识
        bool tcpConnected_; // 建立tcp连接标识
        bool sslConnected_; // 建立ssl成功标识

        unsigned char buf[MAX_BUF_LEN]; // 读写缓冲区(*next指向此缓存区)
        unsigned char* next; // 存放数据指针
        int next_len; // 存放数据长度
        int clientPort_; // 客户端连接端口

        Channel(int epollfd, int fd, int events) : accept_fd_(0), buf{0}, clientPort_(0)
        {
            // 初始化
            epollfd_ = epollfd;
            fd_ = fd;
            events_ = events;

            // 初始化参数
            tfd_ = 0;

            isDeleted_ = false;
            tcpConnected_ = false;
            sslConnected_ = false;

            ssl_ = NULL;
            next = NULL;
            next_len = 0;
        }

        void update()
        {
            struct epoll_event ev;
            memset(&ev, 0, sizeof(ev));
            ev.events = events_;
            ev.data.ptr = this;
            ev.data.fd = fd_;
            int r = epoll_ctl(epollfd_, EPOLL_CTL_MOD, fd_, &ev);
            if (r < 0)
            {
                exit(1);
            }
        }

        ~Channel()
        {
            LOG_INFO("Channel->客户端(%s)已经从服务中移除(%d)\n", clientId_, fd_);
            mutex_.lock();
            isDeleted_ = true;
            // 从epoll中删除
            epoll_ctl(epollfd_, EPOLL_CTL_DEL, fd_, NULL);
            if (fd_ > 0)
            {
                close(fd_);
                fd_ = -1;
            }
            // 删除SSL对象(代理channel中的ssl复用主服务里的ssl，因此这里需要进行判断，避免重复释放ssl)
            if (ssl_)
            {
                LOG_DEBUG("Channel->关闭ssl连接.\n");
                SSL_shutdown(ssl_);
                SSL_free(ssl_);
                ssl_ = NULL;
            }
            mutex_.unlock();
        }
    };
}

#endif
