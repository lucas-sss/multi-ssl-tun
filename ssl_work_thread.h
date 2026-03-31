#include <thread>
#include <future>
#include <vector>
#include <memory>
#include <mutex>
#include <openssl/ssl.h>


#ifndef SSL_WORK_THREAD_H
#define SSL_WORK_THREAD_H

namespace VPN
{
    struct Channel;
    class VIPPool;

    // map安全操作
    bool addVIPChannel(std::string vip, Channel* ch);
    bool delVIPChannel(std::string vip);
    std::mutex& getVIPChannelMutex();
    Channel* findChannel(const char* ip);
    void addFdChannel(int fd, std::shared_ptr<Channel> ch);
    void delFdChannel(int fd);
    std::mutex& getFdChannelMutex();
    std::shared_ptr<Channel> findFdChannel(int fd);

    // ========================================================================================
    void handleSSLError(SSL* ssl, int ret);
    // ========================================================================================

    class SslWorkThread
    {
    public:
        SslWorkThread(int recFd, int tunWriteFd);
        void initThread();
        void startThread(int cpuIndex, std::future<void>& futureObj);
        int getEpollFd() const { return _epollFd; }
        int getRecvFd() const { return _recFd; }

        static int verifyCallback(int preverify_ok, X509_STORE_CTX* x509_ctx);
        static int setNonBlocking(int fd);
        // 将epoll的水平触发修改为边缘触发方式
        static int setEdgeTrigger(int fd);
        void setRunFlag(bool flag) { _runFlag = flag; }
        ~SslWorkThread();

    private:
        void initSSL();
        void handleHandshake(Channel* ch);
        void SslDataRead(Channel* ch);
        void addEpollFd(std::shared_ptr<Channel> ch);
        void createEpoll();
        void handleRead(Channel* ch);
        void handleWrite(Channel* ch);
        void readDispatchMessage(int fd);
        void dispatchFd(int fd);
        void addRecvFdToEpollFd();

        void ThreadFunction(std::future<void> futureObj);

    public:
        static std::string charsToHexStr(unsigned char* data, unsigned int len);
        static std::string charsToHexString(unsigned char* data, unsigned int len); // 16进制转字符串(无空格分隔)

    private:
        int _recFd;
        int _tunWriteFd;
        SSL_CTX* _sslCtx;
        int _epollFd;
        bool _runFlag;

        std::shared_ptr<std::thread> _thread;
        BIO* _errBio;
        std::vector<std::shared_ptr<Channel>> _channelList;
    };
}

#endif
