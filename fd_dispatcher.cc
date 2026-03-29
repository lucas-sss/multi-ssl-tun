#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include "fd_dispatcher.h"
#include "logger.h"


namespace VPN
{
SocketPair::SocketPair(int count):_count(count)
{
}

int SocketPair::InitSocketPair()
{
    for(int i=0; i < _count; i++)
    {
        int fd[2];
        int r = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
        if(r < 0)
        {
            LOG_ERROR("SocketPair Init failed, error:%d\n", r);
            return -1;
        }
        LOG_DEBUG("SocketPair create socket pair: %d, %d\n", fd[0], fd[1]);
        _sendFds.push_back(fd[0]);
        _recvFds.push_back(fd[1]);
    }
    return 0;
}
int SocketPair::getSendFd(int index)
{
    if(_sendFds.size() == 0 || index > (int)(_sendFds.size() - 1))
    {
        return -1;
    }
    else
    {
        return _sendFds[index];
    }
}
int SocketPair::getRecvFd(int index)
{
    if(_recvFds.size() == 0 || index > (int)(_recvFds.size() - 1))
    {
        return -1;
    }
    else
    {
        return _recvFds[index];
    }
}

int SocketPair::sendDispatchMsg(int fd, const struct FdDispatchMsg &msg)
{
    LOG_DEBUG("SocketPair::%s\n", __FUNCTION__);
    int r = -1;
    char buff[128] = {0};
    int size = sizeof(struct FdDispatchMsg);
    if(fd != -1)
    {
        memcpy(buff, &msg, size);
        LOG_INFO("sendDispatchMsg %d, %d, %s, %d, size: %d\n", fd, msg._fd, msg._ip, msg._port, size);
        r = write(fd, buff, size);
        if(r > 0) {
            return 0;
        } else {
            LOG_ERROR("sendDispatchMsg write failed, error:%d\n", r);
            return -1;
        }
    }
    LOG_ERROR("sendDispatchMsg fd is invalid\n");
    return r;
}
int SocketPair::recvDispatchMsg(int fd, struct FdDispatchMsg *msg)
{
    LOG_DEBUG("SocketPair::%s\n", __FUNCTION__);
    int r = -1;
    char buff[128] = {0};
    int size = sizeof(*msg);
    LOG_DEBUG("recvDispatchMsg: %d, size:%d\n", fd, size);
    if(fd != -1)
    {
        r = read(fd, buff, size);
        LOG_INFO("read r: %d\n", r);
        if(r > 0) {
            memcpy(msg, buff, size);
            LOG_INFO("recvDispatchMsg fd %d, ip %s, port %d, family %d\n", msg->_fd, msg->_ip, msg->_port, msg->_family);
            return 0;
        } else {
            LOG_ERROR("recvDispatchMsg read failed, error:%d\n", r);
            return -1;
        }
    }
    LOG_ERROR("recvDispatchMsg fd is invalid\n");
    return r;
}
int SocketPair::getSocketPairCount()
{
    return _count;
}

SocketPair::~SocketPair()
{
    for(int fd : _sendFds)
    {
        close(fd);
    }
    for(int fd : _recvFds)
    {
        close(fd);
    }
}

} // namespace VPN
