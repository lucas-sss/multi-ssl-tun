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

#include "channel.h"


namespace VPN
{
    static std::map<std::string, Channel*> vip_ch_map; // 用于存储所有连接的vip->channel
    static std::map<std::string, Channel*> fd_ch_map; // 用于存储所有连接的fd->channel

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

    bool SslWorkThread::getCertInfo(X509* cert, std::string& subject, std::string& issuer, std::string& serialNo,
                                    std::string& fingerprint, std::string& pubXYString, std::string& validity)
    {
        if (cert != NULL)
        {
            // 获取证书主题信息
            subject = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
            // 获取证书颁发者信息
            issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
            // 获取证书序列号信息
            ASN1_INTEGER* serialNumber = X509_get_serialNumber(cert);
            if (!serialNumber)
            {
                return false;
            }
            // 转换序列号为字符串形式
            char* serialNumberStr = i2s_ASN1_INTEGER(NULL, serialNumber);
            if (!serialNumberStr)
            {
                return false;
            }
            serialNo = serialNumberStr;
            OPENSSL_free(serialNumberStr); // 释放由i2s_ASN1_INTEGER分配的内存
            // 获取证书指纹信息
            unsigned int len = 20;
            unsigned char tmpbuff[32] = {0};
            if (X509_digest(cert, EVP_sha1(), tmpbuff, &len) != 1)
            {
                return false;
            }
            fingerprint = charsToHexString(tmpbuff, len);
            // 获取客户端公钥信息
            EVP_PKEY* pkey = X509_get_pubkey(cert);
            if (pkey)
            {
                if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC)
                {
                    const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey);
                    if (ec_key)
                    {
                        const EC_POINT* point = EC_KEY_get0_public_key(ec_key);
                        if (point)
                        {
                            const EC_GROUP* group = EC_KEY_get0_group(ec_key);
                            if (group)
                            {
                                BIGNUM* x = BN_new();
                                BIGNUM* y = BN_new();
                                if (x && y && EC_POINT_get_affine_coordinates_GFp(group, point, x, y, NULL))
                                {
                                    char* x_str = BN_bn2hex(x);
                                    char* y_str = BN_bn2hex(y);
                                    if (x_str && y_str)
                                    {
                                        pubXYString = std::string(x_str) + std::string(y_str);
                                        LOG_INFO("pubXYString: %s\n", pubXYString.c_str());
                                    }
                                    OPENSSL_free(x_str);
                                    OPENSSL_free(y_str);
                                }
                                // 确保 x 和 y 在所有情况下都被释放
                                BN_free(x);
                                BN_free(y);
                            }
                        }
                    }
                }
                EVP_PKEY_free(pkey);
            }
            // 证书有效期范围信息
            ASN1_TIME* notBefore = X509_get_notBefore(cert);
            ASN1_TIME* notAfter = X509_get_notAfter(cert);
            time_t nowTime = time(NULL);
            time_t iStartTime = convert_ASN1TIME_to_time_t(notBefore);
            time_t iEndTime = convert_ASN1TIME_to_time_t(notAfter);
            char startTime[20] = {0}, endTime[20] = {0};
            if (iStartTime > 0 && iStartTime <= 4294967295)
            {
                strftime(startTime, sizeof(startTime), "%Y-%m-%d %H:%M:%S", localtime(&iStartTime));
                if (nowTime < iStartTime)
                {
                    LOG_WARN("SSLThread::%s 客户端证书尚未生效.\n", __FUNCTION__);
                }
            }
            else
            {
                memcpy(startTime, "null", 4);
            }
            if (iEndTime > 0 && iEndTime <= 4294967295)
            {
                strftime(endTime, sizeof(endTime), "%Y-%m-%d %H:%M:%S", localtime(&iEndTime));
                if (nowTime > iEndTime)
                {
                    LOG_WARN("SSLThread::%s 客户端证书已经过期.\n", __FUNCTION__);
                }
            }
            else
            {
                memcpy(endTime, "null", 4);
            }
            validity = std::string(startTime) + " -> " + std::string(endTime);
            return true;
        }
        return false;
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
            showClientCerts(ch->ssl_); // 此处不展示证书信息
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
        if (ch->ssl_) rlen = SSL_read(ch->ssl_, ch->next + ch->next_len, MAX_BUF_LEN - ch->next_len);
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
                    // LOG_INFO("客户端数据消息: isIPv6_: %d, ch->tfd_: %d\n", ch->isIPv6_, ch->tfd_);
                    // 解析认证类型
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
                    if (datalen > (int)HEADER_LEN)
                        LOG_INFO("客户端登录认证协议: [%02x][%02x] [%02x][%02x]\n", packet[0], packet[1], packet[6], packet[7]);
                    // 客户端登录认证
                    if (memcmp(packet + 6, RECORD_TYPE_AUTH_ACCOUNT, RECORD_TYPE_LABEL_LEN) == 0)
                    {
                        LOG_DEBUG("客户端登录认证: %s\n", packet+HEADER_LEN);
                        // 解析认证数据，判断认证结果，响应客户端，成功推送tun配置
                        if (false == clientLoginAuth(ch, (char*)(packet + HEADER_LEN)))
                        {
                            LOG_WARN("客户端登录认证失败, 关闭连接.\n");
                            // ...
                        }
                        break;
                    }
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
        bool useTLS13 = false;
        std::string signcert = config()->_tlsSigCert; // "certs/signcert.crt";
        std::string signkey = config()->_tlsSigKey; // "certs/signkey.key";
        std::string enccert = config()->_tlsEncCert; // "certs/enccert.crt";
        std::string enckey = config()->_tlsEncKey; // "certs/enckey.key";
        std::string cert = config()->_tlsCert; // "certs/server.pem";
        std::string key = config()->_tlsKey; // "certs/server.pem";
        std::string keypass = config()->_tlsKeyPass; // 证书私钥密码
        std::string tlsCipher = config()->_tlsCipher.c_str(); // 设置密码套件

        SSL_load_error_strings();
        r = SSL_library_init();
        if (!r)
        {
            LOG_INFO("SSL_library_init failed\n");
            exit(0);
        }
        _errBio = BIO_new_fd(2, BIO_NOCLOSE);

        if (config()->_tlsCipherFlag == "RSA")
        {
            _sslCtx = SSL_CTX_new(SSLv23_method()); // 支持TLS1.0及以上版本
            // _sslCtx = SSL_CTX_new(TLS_server_method());  // 支持TLS协议版本
            // _sslCtx = SSL_CTX_new(DTLS_server_method()); // 支持DTLS协议版本
            if (_sslCtx == NULL)
            {
                LOG_INFO("SSL_CTX_new failed\n");
                exit(1);
            }
        }
        else if (config()->_tlsCipherFlag == "SM2")
        {
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
            _sslCtx = SSL_CTX_new(NTLS_server_method()); // 双证书相关server的各种定义
            if (_sslCtx == NULL)
            {
                LOG_INFO("SSL_CTX_new failed\n");
                exit(1);
            }
            SSL_CTX_enable_ntls(_sslCtx); // 允许使用国密双证书功能
        }
        else
        {
            LOG_ERROR("不支持的密码套件.\n");
            exit(1);
        }
#if 0
        if (useTLS13)
        {
            LOG_INFO("enable tls13 sm2 sign\n");
            // tongsuo中tls1.3不强制签名使用sm2签名，使用开关控制，对应客户端指定密码套件SSL_CTX_set_ciphersuites(ctx, "TLS_SM4_GCM_SM3");
            SSL_CTX_enable_sm_tls13_strict(_sslCtx);
            SSL_CTX_set1_curves_list(_sslCtx, "SM2:X25519:prime256v1");
        }
#endif
        // 设置密码套件
        if (tlsCipher.size() > 0)
        {
            LOG_INFO("使用密码套件列表: %s\n", tlsCipher.c_str());
            r = SSL_CTX_set_cipher_list(_sslCtx, tlsCipher.c_str());
            // if(r != 1) {
            //     LOG_ERROR("SSL_CTX_set_cipher_list failed\n");
            //     exit(1);
            // }
        }
        else
        {
            LOG_INFO("使用内置默认密码套件\n");
            // "ECC-SM2-SM4-CBC-SM3:ECDHE-SM2-SM4-CBC-SM3:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"
            r = SSL_CTX_set_cipher_list(
                _sslCtx,
                "ECC-SM2-SM4-CBC-SM3:ECDHE-SM2-SM4-CBC-SM3:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384");
            // if(r != 1) {
            //     LOG_ERROR("SSL_CTX_set_cipher_list failed\n");
            //     exit(1);
            // }
        }
        SSL_CTX_set_options(_sslCtx, SSL_OP_CIPHER_SERVER_PREFERENCE);

        // 是否校验客户端
        if (_verifyClient & !_ca.empty())
        {
            LOG_INFO("开启客户端证书认证 %s\n", _ca.c_str());
            SSL_CTX_set_verify(_sslCtx, SSL_VERIFY_PEER, verifyCallback); // 验证客户端证书回调；
            // SSL_CTX_set_verify(_sslCtx, SSL_VERIFY_CLIENT_ONCE, verifyCallback); // 仅在第一次交互时验证客户端证书
            // SSL_CTX_set_verify_depth(_sslCtx, 0);
            r = SSL_CTX_load_verify_locations(_sslCtx, _ca.c_str(), NULL);
            if (r <= 0)
            {
                ERR_print_errors_fp(stderr);
                LOG_ERROR("SSL_CTX_load_verify_locations %s failed\n", _ca.c_str());
                exit(1);
            }
            ERR_clear_error();
            STACK_OF(X509_NAME)* list = SSL_load_client_CA_file(_ca.c_str());
            if (list == NULL)
            {
                LOG_ERROR("SSL_load_client_CA_file %s failed\n", _ca.c_str());
                exit(1);
            }
            SSL_CTX_set_client_CA_list(_sslCtx, list);
        }
        else if (_verifyClient & !_capath.empty())
        {
            LOG_INFO("开启客户端证书认证. %s\n", _capath.c_str());
            SSL_CTX_set_verify(_sslCtx, SSL_VERIFY_PEER, verifyCallback); // 验证客户端证书回调；
            // SSL_CTX_set_verify(_sslCtx, SSL_VERIFY_CLIENT_ONCE, verifyCallback); // 仅在第一次交互时验证客户端证书
            // SSL_CTX_set_verify_depth(_sslCtx, 0);
            r = SSL_CTX_load_verify_locations(_sslCtx, NULL, _capath.c_str());
            if (r <= 0)
            {
                LOG_ERROR("SSL_CTX_load_verify_locations %s failed\n", _capath.c_str());
                exit(1);
            }
        }
        else
        {
            LOG_INFO("无需验证客户端证书.\n");
            SSL_CTX_set_verify(_sslCtx, SSL_VERIFY_NONE, NULL); // 设置不验证客户端;
        }


        // 是否验证吊销证书
        if (_crl.size() > 0)
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
            r = X509_LOOKUP_load_file(lookup, _crl.c_str(), X509_FILETYPE_PEM);
            if (r <= 0)
            {
                LOG_ERROR("X509_LOOKUP_load_file %s failed\n", _crl.c_str());
                exit(1);
            }
            X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
            LOG_INFO("load _crl finish\n");
        }

        if (keypass.size() > 0)
        {
            // 如果证书私钥需要密码,设置回调
            SSL_CTX_set_default_passwd_cb(_sslCtx, verifyPasswordCallback);
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

        // 这里判断是否需要加载RSA证书
        if (!config()->_tlsCert.empty() && !config()->_tlsKey.empty())
        {
            // 加载rsa证书
            r = SSL_CTX_use_certificate_file(_sslCtx, cert.c_str(), SSL_FILETYPE_PEM);
            if (r <= 0)
            {
                LOG_ERROR("SSL_CTX_use_certificate_file %s failed\n", cert.c_str());
                exit(1);
            }
            r = SSL_CTX_use_PrivateKey_file(_sslCtx, key.c_str(), SSL_FILETYPE_PEM);
            if (r <= 0)
            {
                LOG_ERROR("SSL_CTX_use_PrivateKey_file %s failed\n", key.c_str());
                exit(1);
            }
            LOG_INFO("RSA证书设置完成\n");
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

    int SSLThread::verifyCallback(int preverify_ok, X509_STORE_CTX* x509_ctx)
    {
        LOG_INFO("SSLThread::%s preverify_ok: %d\n", __FUNCTION__, preverify_ok);
        // 获取客户端证书信息
        std::string subject, issuer, serialNo, fingerprint, pubXYString, validity;
        X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
        if (getCertInfo(cert, subject, issuer, serialNo, fingerprint, pubXYString, validity))
        {
            LOG_INFO("客户端证书信息:\n");
            LOG_INFO("使用者: %s\n", subject.c_str());
            LOG_INFO("颁发者: %s\n", issuer.c_str());
            LOG_INFO("序列号: %s\n", serialNo.c_str());
            LOG_INFO("指纹: %s\n", fingerprint.c_str());
            LOG_INFO("公钥XY: %s\n", pubXYString.c_str());
            LOG_INFO("有效期: %s\n", validity.c_str());
        }
        else
        {
            LOG_INFO("无证书信息!\n");
        }

        if (config()->_ignoreExpire == "on")
        {
            // 获取证书验证错误的详细情况
            int err = X509_STORE_CTX_get_error(x509_ctx);
            int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
            if (err == X509_V_ERR_CERT_HAS_EXPIRED)
            {
                // 忽略证书过期错误
                return 1;
            }
        }
        return preverify_ok;
    }

    int SSLThread::verifyPasswordCallback(char* buf, int size, int rwflag, void* u)
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        const char* pass = config()->_tlsKeyPass.c_str(); // 证书私钥密码
        if (strlen(pass) > (size_t)size)
            return -1;
        strcpy(buf, pass);
        return strlen(pass);
    }

    void SSLThread::createEpoll()
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        _epollFd = epoll_create1(EPOLL_CLOEXEC);
    }

    void SSLThread::addEpollFd(std::shared_ptr<Channel> ch)
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

    void SSLThread::readDispatchMessage(int fd)
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        struct FdDispatchMsg msg;
        LOG_DEBUG("SSL Write thread readDispatchMessage: %d\n", fd);
        SocketPair::recvDispatchMsg(fd, &msg);
        dispatchFd(msg._fd, msg._isIPv6);
        LOG_INFO("_channelMap size: %d\n", _channelMap.size());
        LOG_INFO("readDispatchMessage end, %d\n", fd);
        //return msg._fd;
    }

    void SSLThread::showClientCerts(SSL* ssl)
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        // 获取客户端证书信息
        std::string subject, issuer, serialNo, fingerprint, pubXYString, validity;
        X509* cert = SSL_get_peer_certificate(ssl);
        if (getCertInfo(cert, subject, issuer, serialNo, fingerprint, pubXYString, validity))
        {
            LOG_INFO("客户端证书信息:\n");
            LOG_INFO("使用者: %s\n", subject.c_str());
            LOG_INFO("颁发者: %s\n", issuer.c_str());
            LOG_INFO("序列号: %s\n", serialNo.c_str());
            LOG_INFO("指纹: %s\n", fingerprint.c_str());
            LOG_INFO("公钥XY: %s\n", pubXYString.c_str());
            LOG_INFO("有效期: %s\n", validity.c_str());
        }
        else
        {
            LOG_INFO("无证书信息!\n");
        }
    }

    int SSLThread::pushTunConf(Channel* ch)
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        int ret, writeLen = 0;
        _isVirtualIpv6 = config()->_isVirtualIpv6;
        unsigned char conf[512] = {0};
        unsigned char packet[514] = {0};
        unsigned int enpackLen = sizeof(packet);
        cJSON* root = NULL;
        SSL* ssl = ch->ssl_;

        // 判断是否是ipv6
        std::string svip6, cvip6, cidr6;
        // 填充ipv6虚拟地址
        if (_isVirtualIpv6)
        {
            svip6 = _vipPool->getsVip6();
            // cvip6 = _vipPool->allocateVip6();
            cvip6 = _vipPool->allocateVip6() + std::string("/") + _vipPool->getPrefixLen();
            cidr6 = _vipPool->getcidr6();
        }

        // 填充iPV4虚拟地址
        std::string svip, cvip, cidr, cmaskPrefixLen;
        {
            char vip[64] = {0};
            unsigned int vipLen = sizeof(vip);
            memset(vip, 0, sizeof(vip));

            ret = _vipPool->allocateVip(vip, &vipLen);
            if (ret != 0)
            {
                LOG_ERROR("allocate vip fail\n");
                return -1;
            }
            *(vip + vipLen) = '\0';
            svip = ipInt2String(_vipPool->getVip());
            cvip = vip;
            cidr = _vipPool->getipv4net();
            cmaskPrefixLen = _vipPool->getipv4netmask();
        }

        // 记录分配的虚拟ip与ssl对应关系
        ch->setVip((char*)cvip.c_str());
        if (_isVirtualIpv6) ch->setVip6((char*)removePrefixFromIPv6(cvip6).c_str());
        // 记录分配的虚拟ip和channel对应关系
        bool res = false;
        if (_isVirtualIpv6)
        {
            res = addVIPChannel(removePrefixFromIPv6(cvip6), ch);
            if (!res)
            {
                LOG_ERROR("addMaps %s fail\n", removePrefixFromIPv6(cvip6).c_str());
                return -1;
            }
        }
        res = addVIPChannel(cvip, ch);
        if (!res)
        {
            LOG_ERROR("addMaps %s fail\n", cvip.c_str());
            return -1;
        }
        LOG_INFO("allocate vip[%s] success\n", cvip.c_str());

        // 创建配置json
        root = cJSON_CreateObject();
        cJSON_AddNumberToObject(root, "global", _vipPool->_globalBlock);
        cJSON_AddNumberToObject(root, "mtu", _mtu);
        cJSON_AddStringToObject(root, "svip", svip.c_str());
        cJSON_AddStringToObject(root, "cvip", cvip.c_str());
        cJSON_AddStringToObject(root, "cidr", cidr.c_str());
        cJSON_AddStringToObject(root, "cmask", cmaskPrefixLen.c_str());
        if (_isVirtualIpv6)
        {
            cJSON_AddStringToObject(root, "svip6", svip6.c_str());
            cJSON_AddStringToObject(root, "cvip6", cvip6.c_str());
            cJSON_AddStringToObject(root, "cidr6", cidr6.c_str());
            cJSON_AddStringToObject(root, "cmask6", config()->_virtualIpv6Mask.c_str());
        }
        cJSON_AddStringToObject(root, "dns", _dns.c_str());
        char* str = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
        LOG_INFO("推送TUN配置: %s\n", str);

        // 封装数据
        memset(conf, 0, sizeof(conf));
        memcpy(conf, RECORD_TYPE_CONTROL_TUN_CONFIG, RECORD_TYPE_LABEL_LEN);
        memcpy(conf + RECORD_TYPE_LABEL_LEN, str, strlen(str));

        enpack(RECORD_TYPE_CONTROL, conf, strlen(str) + RECORD_TYPE_LABEL_LEN, packet, &enpackLen);

        // 推送数据 TODO 发送数据不全需要处理
        ch->mutex_.lock();
        if (ch->ssl_ != NULL && !ch->isDeleted_) writeLen = SSL_write(ssl, packet, enpackLen);
        ch->mutex_.unlock();
        if (writeLen <= 0)
        {
            LOG_ERROR("网卡配置[%s]推送失败! 错误码: %d, 错误信息: '%s'\n", conf, errno, strerror(errno));
            return -1;
        }

        LOG_DEBUG("SSLThread::%s end\n", __FUNCTION__);
        return 0;
    }

    int SSLThread::pushAccountConf(Channel* ch)
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        // 获取账号安全配置信息
        SECURITY_T security = FileManager::getInstance()->getSecurityInfo();
        unsigned int pwdSurvivalDay = ch->passwordExpiredTime_ <= security.passwordValidDay
                                          ? ch->passwordExpiredTime_
                                          : security.passwordValidDay;

        // 认证结果
        int code = 0;
        std::string msg;
        // 创建JSON
        cJSON* root = NULL;
        root = cJSON_CreateObject();
        cJSON_AddNumberToObject(root, "keepaliveInterval", config()->_iKeepaliveInterval); // 心跳间隔时间
        cJSON_AddNumberToObject(root, "keepaliveTimeout", config()->_iKeepaliveTimeout); // 心跳超时时间
        cJSON_AddNumberToObject(root, "loginTimeout", security.loginTimeout); // 无操作登出时间
        cJSON_AddNumberToObject(root, "loginOutFlow", security.loginOutFlow); // 无操作登出流量
        cJSON_AddStringToObject(root, "pwdRule", security.pwdRole.c_str()); // 密码规则
        cJSON_AddNumberToObject(root, "pwdSurvivalDay", pwdSurvivalDay); // 密码到期时间(单位: 天)
        cJSON_AddNumberToObject(root, "pwdStatus", ch->passwordExpired_); // 密码是否过期，0-正常 1-过期
        cJSON_AddNumberToObject(root, "pwdValidPeriod", security.passwordValidDay); // 密码设置有效期(天)
        cJSON_AddNumberToObject(root, "logLevel", 1); // 日志级别(0~3 debug/info/warn/error)
        cJSON_AddStringToObject(root, "helpMsg", "help msg"); // 帮助对话框消息提示信息
        msg = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
        root = NULL;
        LOG_INFO("推送账户配置: %s\n", msg.c_str());

        // 封装数据
        unsigned char conf[512] = {0};
        unsigned char packet[514] = {0};
        unsigned int enpackLen = sizeof(packet);
        memset(conf, 0, sizeof(conf));
        memcpy(conf, RECORD_TYPE_CONTROL_AUTH_CONFIG, RECORD_TYPE_LABEL_LEN);
        memcpy(conf + RECORD_TYPE_LABEL_LEN, msg.data(), msg.length());
        enpack(RECORD_TYPE_CONTROL, conf, msg.length() + RECORD_TYPE_LABEL_LEN, packet, &enpackLen);

        // 发送数据
        int wlen = 0;
        ch->mutex_.lock();
        if (ch->ssl_ != NULL && !ch->isDeleted_) wlen = SSL_write(ch->ssl_, packet, enpackLen);
        ch->mutex_.unlock();
        if (wlen <= 0)
        {
            LOG_INFO("推送失败! 错误码: %d, 错误信息: '%s'\n", errno, strerror(errno));
            return -1;
        }
        LOG_INFO("SSLThread::%s success\n", __FUNCTION__);
        return 0;
    }

    int SSLThread::pushRouteConf(Channel* ch)
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        // 查询IPv4路由配置表
        std::string ipv4Route = FileManager::getInstance()->getRouteInfo(ch->username_);
        LOG_INFO("IPv4路由配置: %s\n", ipv4Route.c_str());
        // 认证结果
        int code = 0;
        bool isVirtualIpv6 = config()->_isVirtualIpv6;
        std::string msg;
        // 创建JSON
        cJSON* root = NULL;
        root = cJSON_CreateObject();
        // cJSON_AddStringToObject(root, "ipv4_route", config()->_pushRoute.c_str());       // 推送IPv4路由(已废弃,改由查询获取)
        cJSON_AddStringToObject(root, "ipv4_route", ipv4Route.c_str()); // 推送IPv4路由
        if (isVirtualIpv6) cJSON_AddStringToObject(root, "ipv6_route", config()->_pushRoute6.c_str()); // 推送IPv6路由
#if 1   // 正式环境不使用
        std::string resource_msg = FileManager::getInstance()->getClientResourceRuleInfo(ch->username_);
        if (resource_msg.length() > 0)
        {
            cJSON_AddStringToObject(root, "access_resource", resource_msg.c_str());
        }
#endif
        msg = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
        root = NULL;
        // 判断推送路由长度是否超过20480(8000 = 100 * (32 + 48))
        if (msg.length() > 8000)
        {
            LOG_ERROR("推送路由配置超过8000字节, 推送失败!\n");
            return -1;
        }
        LOG_INFO("推送路由配置: %s\n", msg.c_str());

        // 封装数据
        unsigned char conf[10240] = {0};
        unsigned char packet[10240] = {0};
        unsigned int enpackLen = sizeof(packet);
        memset(conf, 0, sizeof(conf));
        memcpy(conf, RECORD_TYPE_CONTROL_ROUTE_CONFIG, RECORD_TYPE_LABEL_LEN);
        memcpy(conf + RECORD_TYPE_LABEL_LEN, msg.data(), msg.length());
        enpack(RECORD_TYPE_CONTROL, conf, msg.length() + RECORD_TYPE_LABEL_LEN, packet, &enpackLen);

        // 发送数据
        int wlen = 0;
        ch->mutex_.lock();
        if (ch->ssl_ != NULL && !ch->isDeleted_) wlen = SSL_write(ch->ssl_, packet, enpackLen);
        ch->mutex_.unlock();
        if (wlen <= 0)
        {
            LOG_INFO("推送失败! 错误码: %d, 错误信息: '%s'\n", errno, strerror(errno));
            return -1;
        }
        LOG_INFO("SSLThread::%s success\n", __FUNCTION__);
        return 0;
    }

    int SSLThread::pushNet2NetConf(Channel* ch)
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        // 获取账号安全配置信息
        SECURITY_T security = FileManager::getInstance()->getSecurityInfo();
        unsigned int pwdSurvivalDay = ch->passwordExpiredTime_ <= security.passwordValidDay
                                          ? ch->passwordExpiredTime_
                                          : security.passwordValidDay;

        // 认证结果
        int code = 0;
        std::string msg;
        // 创建JSON
        cJSON* root = NULL;
        root = cJSON_CreateObject();
        cJSON_AddNumberToObject(root, "keepaliveInterval", config()->_iKeepaliveInterval); // 心跳间隔时间
        cJSON_AddNumberToObject(root, "loginTimeout", security.loginTimeout); // 无操作登出时间
        msg = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
        root = NULL;
        LOG_INFO("推送Net2Net配置: %s\n", msg.c_str());
        // 封装数据
        unsigned char conf[512] = {0};
        unsigned char packet[514] = {0};
        unsigned int enpackLen = sizeof(packet);
        memset(conf, 0, sizeof(conf));
        memcpy(conf, RECORD_TYPE_NET2NET_CONFIG, RECORD_TYPE_LABEL_LEN);
        memcpy(conf + RECORD_TYPE_LABEL_LEN, msg.data(), msg.length());
        enpack(RECORD_TYPE_NET2NET, conf, msg.length() + RECORD_TYPE_LABEL_LEN, packet, &enpackLen);

        // 发送数据
        int wlen = 0;
        ch->mutex_.lock();
        if (ch->ssl_ != NULL && !ch->isDeleted_) wlen = SSL_write(ch->ssl_, packet, enpackLen);
        ch->mutex_.unlock();
        if (wlen <= 0)
        {
            LOG_INFO("推送失败! 错误码: %d, 错误信息: '%s'\n", errno, strerror(errno));
            return -1;
        }
        LOG_INFO("SSLThread::%s success\n", __FUNCTION__);
        return 0;
    }

    char* SSLThread::ipInt2String(int ip_addr)
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        struct in_addr var_ip;
        var_ip.s_addr = htonl(ip_addr);
        return inet_ntoa(var_ip);
    }

    void SSLThread::addRecvFdToEpollFd()
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
        setnoblocking(_recFd); // 设置为非阻塞 (临时测试注释掉)
        if (r)
        {
            LOG_ERROR("epoll_ctl add failed[%d], %s\n", errno, strerror(errno));
            exit(1);
        }
    }

    std::string SSLThread::timestampToDateTime(time_t rawtime)
    {
        if (rawtime <= 0 || rawtime > 2147483647)
        {
            // 如果时间戳非法，返回空字符串。
            return std::string("");
        }
        struct tm* dt;
        char buffer[80];
        dt = localtime(&rawtime);
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", dt);
        std::string str(buffer);
        return str;
    }

    int SSLThread::accountLoginLimit(std::string user, std::string terminal, std::string sessionId, int& errcode,
                                     std::string& errmsg)
    {
        cJSON* root_req = NULL;
        root_req = cJSON_CreateObject();
        cJSON_AddStringToObject(root_req, "username", user.c_str());
        cJSON_AddStringToObject(root_req, "terminalType", terminal.c_str());
        cJSON_AddStringToObject(root_req, "sessionId", sessionId.c_str());
        char* jsondata = cJSON_PrintUnformatted(root_req);
        cJSON_Delete(root_req);
        LOG_DEBUG("request: %s\n", jsondata);
        std::string response = httpRequest->httpsPost("/sslvpn/vpnServer/loginCheck/", jsondata);
        // 字符串查找
        std::size_t found = response.find("{");
        if (found != std::string::npos)
        {
            response = response.substr(found);
            LOG_DEBUG("response: %s\n", response.c_str());
        }
        else
        {
            LOG_ERROR("SSLThread::%s not found '{'.\n", __FUNCTION__);
            return -1;
        }
        // 解析json
        cJSON* root_res = cJSON_Parse(response.c_str());
        if (root_res == NULL)
        {
            LOG_ERROR("SSLThread::%s parse json error\n", __FUNCTION__);
            return -1;
        }
        cJSON* code = cJSON_GetObjectItem(root_res, "code");
        if (code == NULL)
        {
            LOG_ERROR("SSLThread::%s not found code\n", __FUNCTION__);
            return -1;
        }
        cJSON* msg = cJSON_GetObjectItem(root_res, "msg");
        if (msg == NULL)
        {
            LOG_ERROR("SSLThread::%s not found msg\n", __FUNCTION__);
            return -1;
        }
        ErrorInfo err = ERR_SUCCESS;
        if (0 == code->valueint)
        {
            err = ERR_SUCCESS;
        }
        else if (2101 == code->valueint)
        {
            err = ERR_ACCOUNT_NOTFOUND;
        }
        else if (-68 == code->valueint)
        {
            err = ERR_TERMINAL_TYPE;
        }
        else if (-77 == code->valueint)
        {
            err = ERR_IPPOLL_FULL_1;
        }
        else if (-78 == code->valueint)
        {
            err = ERR_LOGIN_LIMIT;
        }
        else
        {
            err = ERR_UNKNOWN;
        }
        LOG_WARN("账号(%s)登录限制, 管理服务响应: errCode=%d, errMsg=%s\n", user.c_str(), code->valueint, msg->valuestring);
        errcode = err.errCode;
        errmsg = err.errMsg;
        return 0;
    }

    int SSLThread::sendSmsCode(std::string& user, std::string& phone, int& errcode, std::string& errmsg)
    {
        ErrorInfo err = ERR_SUCCESS;
        cJSON* root_req = NULL;
        root_req = cJSON_CreateObject();
        cJSON_AddStringToObject(root_req, "username", user.c_str());
        cJSON_AddStringToObject(root_req, "phone", phone.c_str());
        char* jsondata = cJSON_PrintUnformatted(root_req);
        cJSON_Delete(root_req);
        LOG_DEBUG("request: %s\n", jsondata);
        std::string response = httpRequest->httpsPost("/sslvpn/vpnClient/sendPhoneCode", jsondata);
        // 字符串查找
        std::size_t found = response.find("{");
        if (found != std::string::npos)
        {
            response = response.substr(found);
            LOG_DEBUG("response: %s\n", response.c_str());
        }
        else
        {
            LOG_ERROR("sendSmsCode not found '{'.\n");
            return -1;
        }
        // 解析json
        cJSON* root_res = cJSON_Parse(response.c_str());
        if (root_res == NULL)
        {
            LOG_ERROR("sendSmsCode parse json error\n");
            return -1;
        }
        cJSON* code = cJSON_GetObjectItem(root_res, "code");
        if (code == NULL)
        {
            LOG_ERROR("sendSmsCode not found code\n");
            return -1;
        }
        cJSON* msg = cJSON_GetObjectItem(root_res, "msg");
        if (msg == NULL)
        {
            LOG_ERROR("sendSmsCode not found msg\n");
            return -1;
        }
        // 下发短信通知
        if (0 == code->valueint)
        {
            err = ERR_SUCCESS;
        }
        else if (-11100 == code->valueint)
        {
            err = ERR_SMS_SEND_FAILED_1;
        }
        else if (-11101 == code->valueint)
        {
            err = ERR_SMS_SEND_FAILED_2;
        }
        else if (-11102 == code->valueint)
        {
            err = ERR_SMS_SEND_FAILED_3;
        }
        else if (-11103 == code->valueint)
        {
            err = ERR_SMS_SEND_FAILED_4;
        }
        else if (-11104 == code->valueint)
        {
            err = ERR_SMS_SEND_FAILED_5;
        }
        else if (-11105 == code->valueint)
        {
            err = ERR_SMS_SEND_FAILED_6;
        }
        else if (-11106 == code->valueint)
        {
            err = ERR_SMS_SEND_FAILED_7;
        }
        else if (-11107 == code->valueint)
        {
            err = ERR_SMS_SEND_FAILED_8;
        }
        else
        {
            err = ERR_SMS_SEND_FAILED_1;
        }
        errcode = err.errCode;
        errmsg = err.errMsg;
        return 0;
    }

    int SSLThread::modifyPassword(std::string user, std::string oldpass, std::string newpass, int& errcode,
                                  std::string& errmsg)
    {
        cJSON* root_req = NULL;
        root_req = cJSON_CreateObject();
        cJSON_AddStringToObject(root_req, "username", user.c_str());
        cJSON_AddStringToObject(root_req, "oldPassword", oldpass.c_str());
        cJSON_AddStringToObject(root_req, "newPassword", newpass.c_str());
        char* jsondata = cJSON_PrintUnformatted(root_req);
        cJSON_Delete(root_req);
        LOG_DEBUG("request: %s\n", jsondata);
        std::string response = httpRequest->httpsPost("/sslvpn/vpnClient/updatePwd", jsondata);
        // 字符串查找
        std::size_t found = response.find("{");
        if (found != std::string::npos)
        {
            response = response.substr(found);
            LOG_DEBUG("response: %s\n", response.c_str());
        }
        else
        {
            LOG_ERROR("modifyPassword not found '{'.\n");
            return -1;
        }
        // 解析json
        cJSON* root_res = cJSON_Parse(response.c_str());
        if (root_res == NULL)
        {
            LOG_ERROR("modifyPassword parse json error\n");
            return -1;
        }
        cJSON* code = cJSON_GetObjectItem(root_res, "code");
        if (code == NULL)
        {
            LOG_ERROR("modifyPassword not found code\n");
            return -1;
        }
        cJSON* msg = cJSON_GetObjectItem(root_res, "msg");
        if (msg == NULL)
        {
            LOG_ERROR("modifyPassword not found msg\n");
            return -1;
        }
        ErrorInfo err = ERR_SUCCESS;
        if (0 == code->valueint)
        {
            err = ERR_SUCCESS;
        }
        else if (-10000 == code->valueint)
        {
            err = ERR_MODIFY_PASS_FAILED_1;
        }
        else if (-10001 == code->valueint)
        {
            err = ERR_MODIFY_PASS_FAILED_2;
        }
        else if (-10002 == code->valueint)
        {
            err = ERR_MODIFY_PASS_FAILED_3;
        }
        else if (-10003 == code->valueint)
        {
            err = ERR_MODIFY_PASS_FAILED_4;
        }
        else if (-10004 == code->valueint)
        {
            err = ERR_MODIFY_PASS_FAILED_5;
        }
        else if (-10004 == code->valueint)
        {
            err = ERR_MODIFY_PASS_FAILED_6;
        }
        else
        {
            err = ERR_MODIFY_PASS_FAILED_1;
        }
        errcode = err.errCode;
        errmsg = err.errMsg;
        return 0;
    }

    void SSLThread::clientResponse(Channel* ch, const unsigned char* protocol, int errCode, std::string errMsg)
    {
        LOG_INFO("SSLThread::%s\n", __FUNCTION__);
        // 创建响应报文
        std::string response_msg;
        cJSON* response = NULL;
        response = cJSON_CreateObject();
        cJSON_AddNumberToObject(response, "errCode", errCode);
        cJSON_AddStringToObject(response, "errMsg", errMsg.c_str());
        response_msg = cJSON_PrintUnformatted(response);
        cJSON_Delete(response);
        LOG_INFO("response_msg: %s\n", response_msg.c_str());

        // 封装响应数据包
        unsigned char conf[512] = {0};
        unsigned char packet[514] = {0};
        unsigned int packetLen = sizeof(packet);
        memset(conf, 0, sizeof(conf));
        memcpy(conf, response_msg.data(), response_msg.length());
        enpack(protocol, conf, response_msg.length(), packet, &packetLen);

        // 发送响应数据包
        int wlen = 0;
        LOG_INFO("----->clientResponse %s\n", ch->clientId_);
        ch->mutex_.lock();
        LOG_INFO("----->clientResponse111 %s\n", ch->clientId_);
        if (ch->ssl_ != NULL && !ch->isDeleted_) wlen = SSL_write(ch->ssl_, packet, packetLen);
        LOG_INFO("----->clientResponse222 %s\n", ch->clientId_);

        ch->mutex_.unlock();
        if (wlen <= 0)
        {
            LOG_ERROR("发送失败! 错误码: %d, 错误信息: '%s'\n", errno, strerror(errno));
            return;
        }
        LOG_INFO("SSLThread::%s success, wlen: %d\n", __FUNCTION__, wlen);
    }

    // 心跳响应包
    void SSLThread::clientHeartBeat(Channel* ch)
    {
        // LOG_INFO("SSLThread::%s %s\n", __FUNCTION__, ch->clientId_);
        // 创建响应报文
        std::string response_msg = "heartbeat";
        // LOG_INFO("response_msg: %s\n", response_msg.c_str());
        // 封装响应数据包
        unsigned char conf[512] = {0};
        unsigned char packet[514] = {0};
        unsigned int packetLen = sizeof(packet);
        memset(conf, 0, sizeof(conf));
        memcpy(conf, response_msg.data(), response_msg.length());
        enpack(RECORD_TYPE_BEATS, conf, response_msg.length(), packet, &packetLen);

        // 发送响应数据包
        int wlen = 0;
        ch->mutex_.lock();
        if (ch->ssl_ != NULL && !ch->isDeleted_) wlen = SSL_write(ch->ssl_, packet, packetLen);
        ch->mutex_.unlock();
        if (wlen <= 0)
        {
            LOG_ERROR("客户端(%s)心跳响应包发送失败! 错误码: %d, 错误信息: '%s'\n", ch->clientId_, errno, strerror(errno));
            return;
        }
        // LOG_INFO("SSLThread::%s 客户端(%s)心跳响应包发送成功.\n", __FUNCTION__, ch->clientId_);
    }


    int SSLThread::setnoblocking(int fd)
    {
        LOG_DEBUG("SSLThread::%s\n", __FUNCTION__);
        int old_option = fcntl(fd,F_GETFL);
        int new_option = old_option | O_NONBLOCK;
        fcntl(fd,F_SETFL, new_option);
        return old_option;
    }

    int SSLThread::setNonBlock(int fd, bool value)
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

    int SSLThread::setEdgeTrigger(int fd)
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

    // std::shared_ptr<Channel> SSLThread::findChannelMap(int fd)
    // {
    //     auto it = _channelMap.find(fd);
    //     if(it != _channelMap.end())
    //     {
    //         return it->second;
    //     }
    //     else
    //     {
    //         return nullptr;
    //     }
    // }

    // // 根据vip插在channel结构体指针
    // Channel* SSLThread::findChannel(const char *ip)
    // {
    //     // LOG_DEBUG("SSLThread::%s\n", __FUNCTION__); // 日志太多，暂时注释掉
    //     auto iter = maps.find(ip);
    //     if (iter != maps.end()) {
    //         return iter->second;
    //     } else {
    //         return nullptr;
    //     }
    // }
}
