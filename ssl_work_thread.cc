#include "ssl_work_thread.h"

#include <poll.h>
#include <sys/epoll.h>
#include <openssl/md5.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <ctime>
#include <cctype>
#include <string>
#include <cstring>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <map>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/sockios.h>
#include <signal.h>

#include "channel.h"
#include "fd_dispatcher.h"
#include "protocol.h"


namespace VPN
{
    static std::map<std::string, Channel*> vip_ch_map; // 用于存储所有连接的vip->channel
    static std::map<int, std::shared_ptr<Channel>> fd_ch_map; // 用于存储所有连接的fd->channel

    // channel map 线程安全调用处理
    static std::mutex vip_map_mtx; // 全局互斥锁
    static std::mutex fd_map_mtx; // 全局互斥锁

    // ----------------------------------------------------------------------------------------
    bool addVIPChannel(std::string vip, Channel* ch)
    {
        if (vip.empty() || vip == "")
        {
            return false;
        }

        std::lock_guard<std::mutex> lock(vip_map_mtx);
        auto it = vip_ch_map.find(vip);
        if (it == vip_ch_map.end())
        {
            vip_ch_map.insert(std::pair<std::string, Channel*>(vip, ch));
            return true;
        }
        return false;
    }

    bool delVIPChannel(std::string vip)
    {
        if (vip.empty() || vip == "")
        {
            return false;
        }
        std::lock_guard<std::mutex> lock(vip_map_mtx);
        auto it = vip_ch_map.find(vip);
        if (it != vip_ch_map.end())
        {
            it->second->isDeleted_ = true;
            vip_ch_map.erase(vip);
            return true;
        }
        return false;
    }

    // 获取锁
    std::mutex& getVIPChannelMutex()
    {
        return vip_map_mtx;
    }

    // 此函数外部操作时请加锁
    Channel* findChannel(const char* ip)
    {
        std::lock_guard<std::mutex> lock(vip_map_mtx);
        auto it = vip_ch_map.find(ip);
        if (it != vip_ch_map.end())
        {
            return it->second;
        }
        else
        {
            return nullptr; // 或者其他错误处理
        }
    }

    void addFdChannel(int fd, std::shared_ptr<Channel> ch)
    {
        std::lock_guard<std::mutex> lock(fd_map_mtx);
        fd_ch_map[fd] = ch;
    }

    void delFdChannel(int fd)
    {
        std::lock_guard<std::mutex> lock(fd_map_mtx);
        fd_ch_map.erase(fd);
    }

    std::mutex& getFdChannelMutex()
    {
        return fd_map_mtx;
    }

    std::shared_ptr<Channel> findFdChannel(int fd)
    {
        std::lock_guard<std::mutex> lock(fd_map_mtx);
        auto it = fd_ch_map.find(fd);
        if (it == fd_ch_map.end())
        {
            return std::shared_ptr<Channel>();
        }
        return it->second;
    }

    std::string SslWorkThread::charsToHexString(unsigned char* data, unsigned int len)
    {
        static const char* hex = "0123456789abcdef";
        std::string out;
        out.reserve(len * 2);
        for (unsigned int i = 0; i < len; ++i)
        {
            unsigned char b = data[i];
            out.push_back(hex[(b >> 4) & 0x0F]);
            out.push_back(hex[b & 0x0F]);
        }
        return out;
    }

    std::string SslWorkThread::charsToHexStr(unsigned char* data, unsigned int len)
    {
        return charsToHexString(data, len);
    }


    void handleSSLError(SSL* ssl, int ret)
    {
        char buf[256];
        int err = SSL_get_error(ssl, ret);
        switch (err)
        {
        case SSL_ERROR_NONE:
            LOG_ERROR("SSL_ERROR_NONE: No error occurred.\n");
            break;
        case SSL_ERROR_ZERO_RETURN:
            LOG_WARN("SSL_ERROR_ZERO_RETURN: SSL已关闭.\n");
            break;
        case SSL_ERROR_WANT_READ:
            LOG_ERROR("SSL_ERROR_WANT_READ: The operation did not complete; call it again later.\n");
            break;
        case SSL_ERROR_WANT_WRITE:
            LOG_ERROR("SSL_ERROR_WANT_WRITE: The operation did not complete; call it again later.\n");
            break;
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
            LOG_ERROR(
                "SSL_ERROR_WANT_CONNECT or SSL_ERROR_WANT_ACCEPT: The operation did not complete; call it again later.\n");
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:
            LOG_ERROR(
                "SSL_ERROR_WANT_X509_LOOKUP: The operation did not complete because an application callback set by SSL_CTX_set_client_cert_cb() has asked to be called again.\n");
            break;
        case SSL_ERROR_SYSCALL:
            ERR_error_string_n(err, buf, sizeof(buf));
            LOG_INFO("SSL_ERROR_SYSCALL|关闭服务端. err: %d, buf: %s\n", err, buf);
            // stopAppService();
            break;
        case SSL_ERROR_SSL:
            ERR_print_errors_fp(stderr);
            if (ret == 0 && errno == 0)
            {
                LOG_WARN("客户端主动中断了连接.\n");
            }
            else
            {
                ERR_error_string_n(err, buf, sizeof(buf));
                LOG_INFO("SSL_ERROR_SSL|关闭服务端. err: %d, buf: %s\n", err, buf);
                // stopAppService();
            }
            break;
        default:
            ERR_error_string_n(err, buf, sizeof(buf));
            LOG_ERROR("Unknown|未知错误. err: %d, buf: %s\n", err, buf);
            break;
        }
    }

    // 函数声明
    time_t convert_ASN1TIME_to_time_t(ASN1_TIME* time_asn1);

    SslWorkThread::SslWorkThread(int recFd, int tunWriteFd)
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        _tunWriteFd = tunWriteFd;
        _recFd = recFd;
        _runFlag = true;
    }

    void SslWorkThread::initThread()
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        createEpoll();
        addRecvFdToEpollFd();
        initSSL();
    }

    void SslWorkThread::startThread(int cpuIndex, std::future<void>& futureObj)
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        _thread = std::make_shared<std::thread>(&SslWorkThread::ThreadFunction, this, std::move(futureObj));
#if 1
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(cpuIndex, &cpuset);
        int rc = pthread_setaffinity_np(_thread->native_handle(), sizeof(cpu_set_t), &cpuset);
        if (rc != 0)
        {
            LOG_ERROR("Error calling pthread_setaffinity_np: %d\n", rc);
        }
#endif
    }

    void SslWorkThread::ThreadFunction(std::future<void> futureObj)
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        const int kMaxEvents = 1024; // 1024
        struct epoll_event activeEvs[kMaxEvents];
        int recFd = getRecvFd();
        int epollFd = getEpollFd();

        while (futureObj.wait_for(std::chrono::nanoseconds(10)) == std::future_status::timeout)
        {
            int n = epoll_wait(epollFd, activeEvs, kMaxEvents, 100);
            for (int i = n - 1; i >= 0; i--)
            {
                //Channel *ch = (Channel *)activeEvs[i].data.ptr;
                int events = activeEvs[i].events;
                //LOG_INFO("SSL write thread recv data.....:%d, %d, %d", n, activeEvs[i].data.fd, recFd);
                if (events & (EPOLLIN))
                {
                    if (activeEvs[i].data.fd == recFd)
                    {
                        readDispatchMessage(recFd);
                    }
                    else
                    {
                        auto ch = findFdChannel(activeEvs[i].data.fd);
                        if (ch)
                        {
                            handleRead(ch.get());
                        }
                    }
                }
                else if (events & EPOLLOUT)
                {
                    auto ch = findFdChannel(activeEvs[i].data.fd);
                    if (ch)
                    {
                        handleWrite(ch.get());
                    }
                }
                else
                {
                    LOG_INFO("unknown event %d\n", events);
                }
            }
        }
        LOG_INFO("SSL write thread : %ld end.....\n", _thread->get_id());
    }

    void SslWorkThread::handleRead(Channel* ch)
    {
        if (ch->sslConnected_)
        {
            // 已完成ssl握手，读取ssl数
            return SslDataRead(ch);
        }
        return handleHandshake(ch);
    }

    void SslWorkThread::handleWrite(Channel* ch)
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        if (!ch->sslConnected_)
        {
            // 这里主要在ssl握手未完成前由服务端主动处理ssl握手逻辑
            return handleHandshake(ch);
        }
        // 握手完成后不在监听数据可写入事件（频繁触发影响性能）
        ch->events_ &= ~EPOLLOUT;
        ch->update();
    }

    void SslWorkThread::handleHandshake(Channel* ch)
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        LOG_INFO("SSL Write thread hand shake %d\n", ch->fd_);
        if (!ch->tcpConnected_)
        {
            struct pollfd pfd;
            pfd.fd = ch->fd_;
            pfd.events = POLLOUT | POLLERR;
            int r = poll(&pfd, 1, 0);
            if (r == 1 && pfd.revents == POLLOUT)
            {
                LOG_INFO("tcp connected fd %d\n", ch->fd_);
                ch->tcpConnected_ = true;
                ch->events_ = EPOLLIN | EPOLLOUT | EPOLLERR;
                ch->update();
            }
            else
            {
                LOG_ERROR("===================>>>清理.\n");
                LOG_INFO("poll fd %d return %d revents %d\n", ch->fd_, r, pfd.revents);
                delVIPChannel(ch->vip_);
                delFdChannel(ch->fd_);
                LOG_ERROR("===================>>>清理完.\n");
                return;
            }
        }
        if (ch->ssl_ == NULL)
        {
            ch->ssl_ = SSL_new(_sslCtx);
            if (ch->ssl_ == NULL)
            {
                LOG_ERROR("SSL_new failed\n");
                exit(1);
            }
            int r = SSL_set_fd(ch->ssl_, ch->fd_);
            if (!r)
            {
                LOG_ERROR("SSL_set_fd failed\n");
                exit(1);
            }
            SSL_set_accept_state(ch->ssl_);
            LOG_INFO("SSL_set_accept_state end.\n");
        }
        ch->mutex_.lock();
        int r = SSL_accept(ch->ssl_);
        ch->mutex_.unlock();
        if (r == 1)
        {
            ch->sslConnected_ = true;
            ch->tfd_ = _tunWriteFd;
            LOG_INFO("new ssl: %p for fd: %d\n", ch->ssl_, ch->fd_);
            LOG_INFO("SSL_do_handshake end....\n");
            return;
        }
        int err = SSL_get_error(ch->ssl_, r);
        int oldev = ch->events_;
        if (err == SSL_ERROR_WANT_WRITE)
        {
            ch->events_ |= EPOLLOUT;
            ch->events_ &= ~EPOLLIN;
            LOG_INFO("return want write set events %d\n", ch->events_);
            if (oldev == ch->events_)
                return;
            ch->update();
        }
        else if (err == SSL_ERROR_WANT_READ)
        {
            ch->events_ |= EPOLLIN;
            ch->events_ &= ~EPOLLOUT;
            LOG_INFO("return want read set events %d\n", ch->events_);
            if (oldev == ch->events_)
                return;
            ch->update();
        }
        else
        {
            LOG_INFO("SSL_accept return %d error %d errno %d msg %s\n", r, err, errno, strerror(errno));
            ERR_print_errors(_errBio);
            // delVIPChannel(ch->vip_);
            delFdChannel(ch->fd_);
        }
    }

    void SslWorkThread::SslDataRead(Channel* ch)
    {
        int ret = 0;
        unsigned char packet[MAX_BUF_LEN] = {0};
        unsigned int depack_len = 0;

        signal(SIGPIPE, SIG_IGN);
        if (ch->next == NULL)
        {
            ch->next = ch->buf;
            ch->next_len = 0;
        }

        int rlen = 0;
        ch->mutex_.lock();
        if (ch->ssl_)
            rlen = SSL_read(ch->ssl_, ch->next + ch->next_len, MAX_BUF_LEN - ch->next_len);
        ch->mutex_.unlock();
        if (rlen > 0)
        {
            // 2、解包处理
            depack_len = sizeof(packet);
            while ((ret = depack(ch->next, rlen, packet, &depack_len, &ch->next, &ch->next_len)) > 0)
            {
                ch->next_len = rlen; // 重新赋值
                int datalen = depack_len - RECORD_HEADER_LEN;
                // 判定数据类型
                if (memcmp(packet, RECORD_TYPE_DATA, RECORD_TYPE_LABEL_LEN) == 0) // vpn数据
                {
                    if (datalen < (int)RECORD_HEADER_LEN)
                    {
                        continue;
                    }
                    // TODO 资源访问控制判断（判断是否是握手数据包,TCP握手数据包全部允许通过）

                    /* 3、写入到虚拟网卡 */
                    int wlen = write(ch->tfd_, packet + RECORD_HEADER_LEN, datalen);
                    if (wlen < datalen)
                    {
                        LOG_WARN("虚拟网卡写入数据长度小于预期长度, tfd:%d, wlen: %d, datalen: %d, %s\n", ch->tfd_, wlen, datalen,
                                 std::strerror(errno));
                        // TODO 网卡数据写失败处理
                    }
                    if (wlen <= 0)
                    {
                        LOG_WARN("虚拟网卡写入数据失败, tfd:%d, wlen: %d, datalen: %d, %s\n", ch->tfd_, wlen, datalen,
                                 std::strerror(errno));
                        // TODO 网卡数据写失败处理
                    }
                }
                else if (memcmp(packet, RECORD_TYPE_AUTH, RECORD_TYPE_LABEL_LEN) == 0) // 认证数据
                {
                    // 解析认证类型
                    if (datalen < (int)RECORD_HEADER_LEN)
                    {
                        continue;
                    }
                    // TODO 判断认证消息类型
                }
                else
                {
                    // 解析认证类型
                    if (datalen < (int)RECORD_HEADER_LEN)
                    {
                        continue;
                    }
                    // TODO 判断认证消息类型
                    LOG_INFO("未定义协议类型: [%02x][%02x]\n", packet[0], packet[1]);
                }

                depack_len = sizeof(packet);
            }
            return;
        }
        if (rlen <= 0)
        {
            ch->mutex_.lock();
            int ssl_err = SSL_get_error(ch->ssl_, rlen);
            ch->mutex_.unlock();
            if (ssl_err == SSL_ERROR_ZERO_RETURN)
            {
                delVIPChannel(ch->vip_);
                delFdChannel(ch->fd_);
            }
            else if (ssl_err == SSL_ERROR_SSL)
            {
                ERR_print_errors_fp(stderr);
                if (rlen == 0 && errno == 0)
                {
                    LOG_WARN("客户端主动中断了连接.\n");
                }
                else
                {
                    LOG_ERROR("SSL_read return %d, error: %d, errno: %d, msg: %s\n", rlen, ssl_err, errno,
                              strerror(errno));
                }
            }
            else if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
            {
                LOG_ERROR("ssl_error_want(read/write) return %d, error: %d, errno: %d, msg: %s\n", rlen, ssl_err, errno,
                          strerror(errno));
                return;
            }
            else
            {
                LOG_INFO("Connection has been aborted.\n");
            }
            // TODO 上报终端断开事件日志

            delFdChannel(ch->fd_);
            return;
        }
    }


    void SslWorkThread::dispatchFd(int fd)
    {
        std::shared_ptr<Channel> ch(new Channel(_epollFd, fd, EPOLLIN | EPOLLOUT));
        addEpollFd(ch);
        addFdChannel(fd, ch);
    }

    SslWorkThread::~SslWorkThread()
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        if (_epollFd > 0)
        {
            ::close(_epollFd);
        }
        if (_errBio)
        {
            BIO_free(_errBio);
            _errBio = nullptr;
        }
        if (_sslCtx)
        {
            SSL_CTX_free(_sslCtx);
            _sslCtx = nullptr;
        }
        if (_errBio)
        {
            BIO_free(_errBio);
        }
        if (_thread && _thread->joinable())
        {
            _thread->join();
        }
    }

    void SslWorkThread::initSSL()
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        int r;
        std::string ca = "./certs/ca.crt";
        std::string crl;
        std::string signcert = "./certs/signcert.crt";
        std::string signkey = "./certs/signkey.key";
        std::string enccert = "./certs/enccert.crt";
        std::string enckey = "./certs/enckey.key";
        std::string cert = "./certs/server.pem";
        std::string key = "./certs/server.pem";

        SSL_load_error_strings();
        r = SSL_library_init();
        if (!r)
        {
            LOG_INFO("SSL_library_init failed\n");
            exit(0);
        }
        _errBio = BIO_new_fd(2, BIO_NOCLOSE);

#ifdef SDF_ENGINE_ENABLED
        // 判断是否启用加密卡
        if (config()->useEngineSdf)
        {
            LOG_INFO("使用引擎库调用加密卡.\n");
            ENGINE* e = register_engine();
            if (e == NULL)
            {
                LOG_ERROR("register_engine error.\n");
                exit(1);
            }
            // 这里增加密码卡/密码机调用检测
        }
#endif
        LOG_WARN("当前构建环境不启用NTLS，回退到SSLv23_method.\n");
        _sslCtx = SSL_CTX_new(SSLv23_method());
        if (_sslCtx == NULL)
        {
            LOG_INFO("SSL_CTX_new failed\n");
            exit(1);
        }
        // "ECC-SM2-SM4-CBC-SM3:ECDHE-SM2-SM4-CBC-SM3:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"
        r = SSL_CTX_set_cipher_list(_sslCtx, "ECC-SM2-SM4-CBC-SM3");
        if (r != 1)
        {
            LOG_ERROR("SSL_CTX_set_cipher_list failed\n");
            exit(1);
        }
        SSL_CTX_set_options(_sslCtx, SSL_OP_CIPHER_SERVER_PREFERENCE);

        // 是否校验客户端
        if (!ca.empty())
        {
            LOG_INFO("开启客户端证书认证. %s\n", ca.c_str());
            SSL_CTX_set_verify(_sslCtx, SSL_VERIFY_PEER, verifyCallback); // 验证客户端证书回调；
            // SSL_CTX_set_verify(_sslCtx, SSL_VERIFY_CLIENT_ONCE, verifyCallback); // 仅在第一次交互时验证客户端证书
            // SSL_CTX_set_verify_depth(_sslCtx, 0);
            r = SSL_CTX_load_verify_locations(_sslCtx, NULL, ca.c_str());
            if (r <= 0)
            {
                LOG_ERROR("SSL_CTX_load_verify_locations %s failed\n", ca.c_str());
                exit(1);
            }
        }
        else
        {
            LOG_INFO("无需验证客户端证书.\n");
            SSL_CTX_set_verify(_sslCtx, SSL_VERIFY_NONE, NULL); // 设置不验证客户端;
        }


        // 是否验证吊销证书
        if (!crl.empty())
        {
            X509_STORE* store = NULL;
            X509_LOOKUP* lookup = NULL;

            store = SSL_CTX_get_cert_store(_sslCtx);
            if (store == NULL)
            {
                LOG_ERROR("SSL_CTX_get_cert_store() failed\n");
                exit(1);
            }
            lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
            if (lookup == NULL)
            {
                LOG_ERROR("X509_STORE_add_lookup() failed\n");
                exit(1);
            }
            r = X509_LOOKUP_load_file(lookup, crl.c_str(), X509_FILETYPE_PEM);
            if (r <= 0)
            {
                LOG_ERROR("X509_LOOKUP_load_file %s failed\n", crl.c_str());
                exit(1);
            }
            X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
            LOG_INFO("load _crl finish\n");
        }

        // 加载sm2证书
        // 国密密码套件必须支持(ECC-SM2-SM4-CBC-SM3、ECDHE-SM2-SM4-CBC-SM3)
        if (!signkey.empty() && !signcert.empty() && !enccert.empty() && !enckey.empty())
        {
            r = SSL_CTX_use_sign_PrivateKey_file(_sslCtx, signkey.c_str(), SSL_FILETYPE_PEM);
            if (r <= 0)
            {
                LOG_ERROR("SSL_CTX_use_sign_PrivateKey_file %s failed\n", signkey.c_str());
                exit(1);
            }
            r = SSL_CTX_use_sign_certificate_file(_sslCtx, signcert.c_str(), SSL_FILETYPE_PEM);
            if (r <= 0)
            {
                LOG_ERROR("SSL_CTX_use_sign_certificate_file %s failed\n", signcert.c_str());
                exit(1);
            }
            r = SSL_CTX_use_enc_PrivateKey_file(_sslCtx, enckey.c_str(), SSL_FILETYPE_PEM);
            if (r <= 0)
            {
                LOG_ERROR("SSL_CTX_use_enc_PrivateKey_file %s failed\n", enckey.c_str());
                exit(1);
            }
            r = SSL_CTX_use_enc_certificate_file(_sslCtx, enccert.c_str(), SSL_FILETYPE_PEM);
            if (r <= 0)
            {
                LOG_ERROR("SSL_CTX_use_enc_PrivateKey_file %s failed\n", enckey.c_str());
                exit(1);
            }
            LOG_INFO("SM2证书设置完成.\n");
        }

        r = SSL_CTX_check_private_key(_sslCtx);
        if (!r)
        {
            LOG_ERROR("SSL_CTX_check_private_key failed\n");
            exit(1);
        }
        LOG_INFO("SSL初始化完成.\n");
    }

    time_t convert_ASN1TIME_to_time_t(ASN1_TIME* time_asn1)
    {
        struct tm t;
        const char* str = (const char*)time_asn1->data;
        if (time_asn1->type == V_ASN1_UTCTIME)
        {
            //两位年份
            sscanf(str, "%2d%2d%2d%2d%2d", &t.tm_year, &t.tm_mon - 1, &t.tm_mday, &t.tm_hour, &t.tm_min);
            t.tm_year += 2000 - 1900;
        }
        else if (time_asn1->type == V_ASN1_GENERALIZEDTIME)
        {
            //四位年份
            sscanf(str, "%4d%2d%2d%2d%2d", &t.tm_year, &t.tm_mon - 1, &t.tm_mday, &t.tm_hour, &t.tm_min);
            t.tm_year -= 1900;
        }
        t.tm_sec = 0;
        t.tm_isdst = -1;
        return mktime(&t);
    }

    int SslWorkThread::verifyCallback(int preverify_ok, X509_STORE_CTX* x509_ctx)
    {
        LOG_INFO("SSLThread::%s preverify_ok: %d\n", __FUNCTION__, preverify_ok);
        // 获取证书验证错误的详细情况
        int err = X509_STORE_CTX_get_error(x509_ctx);
        if (err == X509_V_ERR_CERT_HAS_EXPIRED)
        {
            // 忽略证书过期错误
            return 1;
        }
        return preverify_ok;
    }

    void SslWorkThread::createEpoll()
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        _epollFd = epoll_create1(EPOLL_CLOEXEC);
    }

    void SslWorkThread::addEpollFd(std::shared_ptr<Channel> ch)
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        //ev.events = ch->events_;
        //ev.data.ptr = ch.get();
        ev.data.fd = ch->fd_;
        // ev.events = EPOLLIN | EPOLLET; // 边缘触发
        ev.events = EPOLLIN; // 水平触发
        int r = epoll_ctl(_epollFd, EPOLL_CTL_ADD, ch->fd_, &ev);
        LOG_INFO("adding fd %d events %ld\n", ch->fd_, ev.events);
        if (r)
        {
            LOG_ERROR("epoll_ctl add failed[%d], %s\n", errno, strerror(errno));
            exit(1);
        }
    }

    void SslWorkThread::readDispatchMessage(int fd)
    {
        struct FdDispatchMsg msg;
        LOG_DEBUG("SSL Write thread readDispatchMessage: %d\n", fd);
        SocketPair::recvDispatchMsg(fd, &msg);
        dispatchFd(msg._fd);
    }

    void SslWorkThread::addRecvFdToEpollFd()
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.data.fd = _recFd;
        //ev.data.ptr = nullptr;
        // ev.events = EPOLLIN | EPOLLET; // 边缘触发
        ev.events = EPOLLIN; // 水平触发
        LOG_DEBUG("SSL Write thread adding rec fd %d events %ld\n", _recFd, ev.events);
        int r = epoll_ctl(_epollFd, EPOLL_CTL_ADD, _recFd, &ev);
        setNonBlocking(_recFd); // 设置为非阻塞 (临时测试注释掉)
        if (r)
        {
            LOG_ERROR("epoll_ctl add failed[%d], %s\n", errno, strerror(errno));
            exit(1);
        }
    }


    int SslWorkThread::setNonBlocking(int fd)
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        int old_option = fcntl(fd,F_GETFL);
        int new_option = old_option | O_NONBLOCK;
        fcntl(fd,F_SETFL, new_option);
        return old_option;
    }

    int SslWorkThread::setEdgeTrigger(int fd)
    {
        // 设置文件描述符为非阻塞模式
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1)
        {
            // std::cerr << "Failed to get file descriptor flags." << std::endl;
            return 1;
        }
        flags |= O_NONBLOCK;
        if (fcntl(fd, F_SETFL, flags) == -1)
        {
            // std::cerr << "Failed to set file descriptor to non-blocking." << std::endl;
            return 1;
        }

        // 创建epoll_event结构体，并设置边缘触发模式
        epoll_event event;
        event.events = EPOLLIN | EPOLLET; // EPOLLIN表示可读事件，EPOLLET表示边缘触发
        event.data.fd = fd;

        return 0;
    }
}
