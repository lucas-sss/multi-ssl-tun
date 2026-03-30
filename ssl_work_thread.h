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
        void joinThread();
        int getEpollFd() const { return _epollFd; }
        int getRecvFd() const { return _recFd; }

        static int verifyCallback(int preverify_ok, X509_STORE_CTX* x509_ctx);
        static int verifyPasswordCallback(char* buf, int size, int rwflag, void* u);

        static int setnoblocking(int fd);
        static int setNonBlock(int fd, bool value);
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
        void showClientCerts(SSL* ssl);
        void dispatchFd(int fd);
        void addRecvFdToEpollFd();

        void ThreadFunction(std::future<void> futureObj);

    public:
        static std::string charsToHexStr(unsigned char* data, unsigned int len);
        static std::string charsToHexString(unsigned char* data, unsigned int len); // 16进制转字符串(无空格分隔)
        std::string removePrefixFromIPv6(const std::string ipv6WithPrefix);

        // 证书相关
        // 获取证书主题,颁发者,序列号,指纹信息
        static bool getCertInfo(X509* cert, std::string& subject, std::string& issuer, std::string& serialNo,
                                std::string& fingerprint, std::string& pubXYString, std::string& validity);

        // 字符串转小写
        static std::string toLower(std::string str);

    public:
        // 客户端登录认证响应
        bool clientLoginAuth(Channel* ch, std::string data);
        void clientLoginAuthRespose(Channel* ch, int loginType, int errCode, std::string errMsg);
        void clientLoginSmsAuthRespose(Channel* ch, int loginType, std::string phoneNum, int errCode,
                                       std::string errMsg); // 鉴权方式包含短信验证时调用
        void clientNoticeResponse(Channel* ch, int loginType, int errCode, std::string errMsg);
        // 客户端登录/退出时调用脚本
        void clientLoginLogout(bool loginFlag, std::string username);
        // 客户端重新连接时
        void clientReconnectSSL(Channel* ch);
        // 客户端心跳检查(已经弃用，客户端检测)
        void clientHeartBeatCheck(Channel* ch);
        // 登录顶替检查/下线通知
        void clientShutdownCheck(Channel* ch);

        // 设置网对网模式channel
        void setNet2NetChannel(Channel* ch);

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
