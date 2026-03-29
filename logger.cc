#include "logger.h"
#include <iostream>
#include <thread>
#include <memory>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
// #include <pthread.h>
#include <stdarg.h>
#include <signal.h>
#include <syslog.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>

// #include "flk_sm3.h"

// // 日志级别定义
#define LOG_LEVEL_NONE          0x00
// #define LOG_LEVEL_INFO          0x01
// #define LOG_LEVEL_DEBUG         0x02
// #define LOG_LEVEL_WARN          0x04
// #define LOG_LEVEL_ERROR         0x08

// #define LOG_LEVEL_MNG_T         0x10
// #define LOG_LEVEL_MNG_E         0x20

// 参数配置
#define MAX_MSG_SIZE_PRE        5
#define LOG_MSG_ERR             100
#define LOG_MSG_SIZE            4096
#define LOG_SIZE_1GB            1073741824L  // 1GB
#define MSGLOGKEY               15

// 日志文件存储路径定义
#define LOG_APPS_PATH           "/var/apps/"
#define LOG_FILE_PATH           "/var/apps/logs/"
#define LOG_FILE_PATH_PRODUCT   "/var/apps/logs/%s"
#define LOG_FILE_PATH_ALL       "/var/apps/logs/%s/"
#define LOG_FILE_PATH_INFO      "/var/apps/logs/%s/info"
#define LOG_FILE_PATH_DEBUG     "/var/apps/logs/%s/debug"
#define LOG_FILE_PATH_WARN      "/var/apps/logs/%s/warn"
#define LOG_FILE_PATH_ERROR     "/var/apps/logs/%s/error"

// 日志配置文件路径
#define LOG_CONFIG_FILE         "/var/apps/data/LOGConf.ini"

// 结构体定义
typedef struct
{
    unsigned int iMsgIDLog;
} HSM_MSGID_ST;

typedef struct
{
    long mtype;
    unsigned char mtext[4096];
} MYMSG_ST;


HSM_MSGID_ST* gpstMsg = NULL;

CLogger* CLogger::instance = nullptr;

CLogger::CLogger()
{
    m_productName.clear();
    m_serviceName.clear();

    g_msgkey = 0;
    g_syslog = 0;
    g_logsplit = 0;
    g_loglevel = 0;
    g_logSavingDays = 0;
    g_logCleanTotalDays = 365;

    // stdoutEnable = false;
    g_stdoutEnable = true;
    // 创建日志文件存储路径
    createDirectory(LOG_APPS_PATH);
    createDirectory(LOG_FILE_PATH);
}

CLogger::~CLogger()
{
    joinThread();
}

int CLogger::initCLogger(const std::string& productName, const std::string& serviceName)
{
    // 设置产品名称/服务模块名称
    m_productName = productName;
    m_serviceName = serviceName;

    // 检查日志文件路径是否存在
    char productLogPath[256] = {0};
    sprintf(productLogPath, LOG_FILE_PATH_PRODUCT, productName.c_str());
    if (false == createDirectory(productLogPath))
    {
        return -1;
    }
    // 分配空间
    if (false == shmapiGetShm())
    {
        return -5;
    }
    g_msgkey = (unsigned int)calcCRC((char*)m_productName.c_str(), m_productName.length());

    if (0 != shmapiInit())
    {
        perror("shmapiInit error\n");
        return -6;
    }

    // 开启线程
    g_threadLog = std::make_shared<std::thread>(&CLogger::threadLogFunc, this);
    g_threadTimer = std::make_shared<std::thread>(&CLogger::threadTimerFunc, this);

    return 0;
}

int CLogger::asyncLogWrite(int type, char* file, int line, char* ip, const char* fmt, ...)
{
    // printf("type: %d, file: %s, line: %d, ip: %s\n", type, file, line, ip);
    static va_list ap;
    unsigned int counter = 0;
    unsigned int len;
    int iret = 0;
    MYMSG_ST sendbuf;
    if ((g_loglevel & type) == 0)
    {
        return 0;
    }
    if (file == NULL || ip == NULL)
    {
        return -1;
    }
    memset(&sendbuf, 0, sizeof(MYMSG_ST));
    sendbuf.mtext[counter++] = type;
    sendbuf.mtext[counter++] = 0;
    sendbuf.mtext[counter++] = 0;
    counter += snprintf((char*)(sendbuf.mtext + counter), 4096 - counter,
                        "time:%s|pid:%d|file:%s|line:%d|client_ip:%s|",
                        getLogTime() + 11,
                        getpid(),
                        file,
                        line,
                        ip);

    va_start(ap, fmt);
    counter += vsnprintf((char*)(sendbuf.mtext + counter), 4096 - counter, fmt, ap);
    va_end(ap);

#if 0
    byte dgst[FLK_SM3_DIGEST_LENGTH] = {0};
    byte base64dgst[128] = {0};
    flk_sm3_hmac((unsigned char*)"1234567812345678", 16, sendbuf.mtext + 3, (size_t)(counter - 3), dgst);
    base64_encode((char*)base64dgst, (char*)dgst, 32);
    counter += snprintf((char*)sendbuf.mtext + counter, 4096 - counter, "[HMAC:%s]\n", base64dgst);
#endif

    sendbuf.mtext[1] = (unsigned char)((counter - 3) / 256);
    sendbuf.mtext[2] = (unsigned char)((counter - 3) % 256);

    if (gpstMsg)
    {
        sendbuf.mtype = 1;
        iret = shmapiSendMsgLog(gpstMsg->iMsgIDLog, (unsigned char*)&sendbuf, counter, 0);
    }

    return iret;
}

int CLogger::syncLogwrite(int type, char* file, int line, char* ip, const char* fmt, ...)
{
    static va_list ap;
    char temp[4096] = {0};
    short len;
    if (file == NULL || ip == NULL)
    {
        return -1;
    }
    if ((type != LOG_LEVEL_MNG_T) && (type != LOG_LEVEL_MNG_E))
    {
        printf("flk_log_sync_write type[%x] error, must be LOG_LEVEL_MNG_T[%x] or LOG_LEVEL_MNG_E[%x]!\n", type,
               LOG_LEVEL_MNG_T, LOG_LEVEL_MNG_E);
        return -2;
    }
    memset(temp, 0, 4096);
    len = snprintf(temp, 4096, "[%s][%d][%s][%d][%s]",
                   getLogTime() + 11,
                   getpid(),
                   file,
                   line,
                   ip);
    va_start(ap, fmt);
    len += vsnprintf(temp + len, 4096 - len, fmt, ap);
    va_end(ap);
#if 0
    byte dgst[FLK_SM3_DIGEST_LENGTH] = {0};
    byte base64dgst[128] = {0};
    flk_sm3_hmac((unsigned char*)"1234567812345678", 16, (unsigned char*)temp, (size_t)len, dgst);
    base64_encode((char*)base64dgst, (char*)dgst, 32);
    len += snprintf(temp + len, 4096 - len, "[HMAC:%s]\n", base64dgst);
#endif

    logWriteLog(type, temp, len);

    if (g_syslog > 0)
    {
        if (type == LOG_LEVEL_MNG_E)
        {
            syslog(LOG_SYSLOG | LOG_ERR, "%s", temp);
        }
        else
        {
            syslog(LOG_SYSLOG | LOG_INFO, "%s", temp);
        }
    }
    return 0;
}

CLogger* CLogger::getInstance(const std::string& productName, const std::string& serviceName, bool daemon)
{
    if (instance == nullptr)
    {
        instance = new CLogger();
        instance->initCLogger(productName, serviceName);
        instance->setStdoutEnable(!daemon);
    }
    return instance;
}

void CLogger::debug(const char* fmt, ...)
{
    std::lock_guard<std::mutex> lock(log_mutex);
    static va_list ap;
    unsigned int counter = 0;
    unsigned int len;
    int iret = 0;
    MYMSG_ST sendbuf;
    // std::cout << "g_loglevel = " << g_loglevel << std::endl;
    if ((g_loglevel & LOG_LEVEL_DEBUG) == 0)
    {
        return;
    }
    memset(&sendbuf, 0, sizeof(MYMSG_ST));
    sendbuf.mtext[counter++] = LOG_LEVEL_DEBUG;
    sendbuf.mtext[counter++] = 0;
    sendbuf.mtext[counter++] = 0;
    counter += snprintf((char*)(sendbuf.mtext + counter), 4096 - counter, "[%s] [DEBUG] [%d] ", getLogTime(), getpid());

    va_start(ap, fmt);
    counter += vsnprintf((char*)(sendbuf.mtext + counter), 4096 - counter, fmt, ap);
    va_end(ap);

    // 输出到终端
    if (g_stdoutEnable)
    {
        printf("%s", (char*)(sendbuf.mtext + 3));
        // return;
    }

#if 0
    byte dgst[FLK_SM3_DIGEST_LENGTH] = {0};
    byte base64dgst[128] = {0};
    flk_sm3_hmac((unsigned char*)"1234567812345678", 16, sendbuf.mtext + 3, (size_t)(counter - 3), dgst);
    base64_encode((char*)base64dgst, (char*)dgst, 32);
    counter += snprintf((char*)sendbuf.mtext + counter, 4096 - counter, "[HMAC:%s]\n", base64dgst);
#endif
    if (counter > 4096) return;
    sendbuf.mtext[1] = (unsigned char)((counter - 3) / 256);
    sendbuf.mtext[2] = (unsigned char)((counter - 3) % 256);
    if (gpstMsg)
    {
        sendbuf.mtype = 1;
        iret = shmapiSendMsgLog(gpstMsg->iMsgIDLog, (unsigned char*)&sendbuf, counter, 0);
    }
    // std::cout << "iret = " << iret << std::endl;
}

void CLogger::info(const char* fmt, ...)
{
    std::lock_guard<std::mutex> lock(log_mutex);
    static va_list ap;
    unsigned int counter = 0;
    unsigned int len;
    int iret = 0;
    MYMSG_ST sendbuf;
    if ((g_loglevel & LOG_LEVEL_INFO) == 0)
    {
        return;
    }
    memset(&sendbuf, 0, sizeof(MYMSG_ST));
    sendbuf.mtext[counter++] = LOG_LEVEL_INFO;
    sendbuf.mtext[counter++] = 0;
    sendbuf.mtext[counter++] = 0;
    counter += snprintf((char*)(sendbuf.mtext + counter), 4096 - counter, "[%s] [INFO ] [%d] ", getLogTime(), getpid());

    va_start(ap, fmt);
    counter += vsnprintf((char*)(sendbuf.mtext + counter), 4096 - counter, fmt, ap);
    va_end(ap);

    // 输出到终端
    if (g_stdoutEnable)
    {
        printf("%s", (char*)(sendbuf.mtext + 3));
        // return;
    }

#if 0
    byte dgst[FLK_SM3_DIGEST_LENGTH] = {0};
    byte base64dgst[128] = {0};
    flk_sm3_hmac((unsigned char*)"1234567812345678", 16, sendbuf.mtext + 3, (size_t)(counter - 3), dgst);
    base64_encode((char*)base64dgst, (char*)dgst, 32);
    counter += snprintf((char*)sendbuf.mtext + counter, 4096 - counter, "[HMAC:%s]\n", base64dgst);
#endif
    if (counter > 4096) return;
    sendbuf.mtext[1] = (unsigned char)((counter - 3) / 256);
    sendbuf.mtext[2] = (unsigned char)((counter - 3) % 256);
    if (gpstMsg)
    {
        sendbuf.mtype = 1;
        iret = shmapiSendMsgLog(gpstMsg->iMsgIDLog, (unsigned char*)&sendbuf, counter, 0);
    }
    // std::cout << "iret = " << iret << std::endl;
}

void CLogger::warn(const char* fmt, ...)
{
    std::lock_guard<std::mutex> lock(log_mutex);
    static va_list ap;
    unsigned int counter = 0;
    unsigned int len;
    int iret = 0;
    MYMSG_ST sendbuf;
    if ((g_loglevel & LOG_LEVEL_WARN) == 0)
    {
        return;
    }
    memset(&sendbuf, 0, sizeof(MYMSG_ST));
    sendbuf.mtext[counter++] = LOG_LEVEL_WARN;
    sendbuf.mtext[counter++] = 0;
    sendbuf.mtext[counter++] = 0;
    counter += snprintf((char*)(sendbuf.mtext + counter), 4096 - counter, "[%s] [WARN ] [%d] ", getLogTime(), getpid());

    va_start(ap, fmt);
    counter += vsnprintf((char*)(sendbuf.mtext + counter), 4096 - counter, fmt, ap);
    va_end(ap);

    // 输出到终端
    if (g_stdoutEnable)
    {
        printf("%s", (char*)(sendbuf.mtext + 3));
        // return;
    }

#if 0
    byte dgst[FLK_SM3_DIGEST_LENGTH] = {0};
    byte base64dgst[128] = {0};
    flk_sm3_hmac((unsigned char*)"1234567812345678", 16, sendbuf.mtext + 3, (size_t)(counter - 3), dgst);
    base64_encode((char*)base64dgst, (char*)dgst, 32);
    counter += snprintf((char*)sendbuf.mtext + counter, 4096 - counter, "[HMAC:%s]\n", base64dgst);
#endif
    if (counter > 4096) return;
    sendbuf.mtext[1] = (unsigned char)((counter - 3) / 256);
    sendbuf.mtext[2] = (unsigned char)((counter - 3) % 256);
    if (gpstMsg)
    {
        sendbuf.mtype = 1;
        iret = shmapiSendMsgLog(gpstMsg->iMsgIDLog, (unsigned char*)&sendbuf, counter, 0);
    }
    // std::cout << "iret = " << iret << std::endl;
}

void CLogger::error(const char* fmt, ...)
{
    std::lock_guard<std::mutex> lock(log_mutex);
    static va_list ap;
    unsigned int counter = 0;
    unsigned int len;
    int iret = 0;
    MYMSG_ST sendbuf;
    if ((g_loglevel & LOG_LEVEL_ERROR) == 0)
    {
        return;
    }
    memset(&sendbuf, 0, sizeof(MYMSG_ST));
    sendbuf.mtext[counter++] = LOG_LEVEL_ERROR;
    sendbuf.mtext[counter++] = 0;
    sendbuf.mtext[counter++] = 0;
    counter += snprintf((char*)(sendbuf.mtext + counter), 4096 - counter, "[%s] [ERROR] [%d] ", getLogTime(), getpid());

    va_start(ap, fmt);
    counter += vsnprintf((char*)(sendbuf.mtext + counter), 4096 - counter, fmt, ap);
    va_end(ap);

    // 输出到终端
    if (g_stdoutEnable)
    {
        printf("%s", (char*)(sendbuf.mtext + 3));
        // return;
    }

#if 0
    byte dgst[FLK_SM3_DIGEST_LENGTH] = {0};
    byte base64dgst[128] = {0};
    flk_sm3_hmac((unsigned char*)"1234567812345678", 16, sendbuf.mtext + 3, (size_t)(counter - 3), dgst);
    base64_encode((char*)base64dgst, (char*)dgst, 32);
    counter += snprintf((char*)sendbuf.mtext + counter, 4096 - counter, "[HMAC:%s]\n", base64dgst);
#endif
    if (counter > 4096) return;
    sendbuf.mtext[1] = (unsigned char)((counter - 3) / 256);
    sendbuf.mtext[2] = (unsigned char)((counter - 3) % 256);
    if (gpstMsg)
    {
        sendbuf.mtype = 1;
        iret = shmapiSendMsgLog(gpstMsg->iMsgIDLog, (unsigned char*)&sendbuf, counter, 0);
    }
    // std::cout << "iret = " << iret << std::endl;
}

bool CLogger::createDirectory(const std::string& dirPath)
{
    struct stat st;
    // stat()返回0表示成功，即路径存在，否则不存在
    if (stat(dirPath.c_str(), &st) == -1)
    {
        // 使用mkdir创建目录，S_IRWXU表示用户具有读、写和执行权限
        if (mkdir(dirPath.c_str(), S_IRWXU) == -1)
        {
            perror("createDirectory failed\n");
            return false;
        }
    }
    return true;
}

bool CLogger::shmapiGetShm()
{
    gpstMsg = (HSM_MSGID_ST*)malloc(sizeof(HSM_MSGID_ST));
    if (gpstMsg == NULL)
    {
        perror("shmat");
        return false;
    }
    return true;
}

bool CLogger::deleteLogFile(std::string file)
{
    if ((access(file.c_str(), F_OK) == 0) && (remove(file.c_str()) == 0))
    {
        return true;
    }
    return false;
}

// 日志定时清理函数
bool CLogger::cleanLogFile()
{
    if (g_logCleanTotalDays < g_logSavingDays) return false;
    for (int i = g_logCleanTotalDays; i > g_logSavingDays; i--)
    {
        char delDateTime[32] = {0};
        time_t delTime = time(NULL) - 86400 * i;
        struct tm* stDelTM = localtime(&delTime);
        sprintf(delDateTime, "%04d-%02d-%02d", stDelTM->tm_year + 1900, stDelTM->tm_mon + 1, stDelTM->tm_mday);
        if (delDateTime <= m_recordDelLogTime)
        {
            // debug("最后日志清理日期: %s\n", m_recordDelLogTime.c_str());
            return true;
        }
        m_recordDelLogTime = delDateTime;
        char all_log[128] = {0}, debug_log[128] = {0}, info_log[128] = {0}, warn_log[128] = {0}, error_log[128] = {0};
        sprintf((char*)all_log, LOG_FILE_PATH_ALL"all.%s.%s.log", (char*)m_productName.c_str(), m_serviceName.c_str(),
                delDateTime);
        sprintf((char*)debug_log, LOG_FILE_PATH_DEBUG"/debug.%s.%s.log", (char*)m_productName.c_str(),
                m_serviceName.c_str(), delDateTime);
        sprintf((char*)info_log, LOG_FILE_PATH_INFO"/info.%s.%s.log", (char*)m_productName.c_str(),
                m_serviceName.c_str(), delDateTime);
        sprintf((char*)warn_log, LOG_FILE_PATH_WARN"/warn.%s.%s.log", (char*)m_productName.c_str(),
                m_serviceName.c_str(), delDateTime);
        sprintf((char*)error_log, LOG_FILE_PATH_ERROR"/error.%s.%s.log", (char*)m_productName.c_str(),
                m_serviceName.c_str(), delDateTime);

        bool result = false;
        result = deleteLogFile(all_log);
        if (result)
        {
            info("清理日志: %s\n", all_log);
        }
        result = deleteLogFile(debug_log);
        if (result)
        {
            info("清理日志: %s\n", debug_log);
        }
        result = deleteLogFile(info_log);
        if (result)
        {
            info("清理日志: %s\n", info_log);
        }
        result = deleteLogFile(warn_log);
        if (result)
        {
            info("清理日志: %s\n", warn_log);
        }
        result = deleteLogFile(error_log);
        if (result)
        {
            info("清理日志: %s\n", error_log);
        }
    }
    g_logCleanTotalDays = g_logSavingDays + 1;
    return true;
}

unsigned char CLogger::calcCRC(char* strData, int len)
{
    char checksum = 0;
    int i;
    for (i = 0; i < len; i++)
    {
        checksum = checksum ^ strData[i];
    }
    return (unsigned char)checksum;
}

int CLogger::str2int(std::string str)
{
    try
    {
        long num = std::stoi(str);
        return num;
    }
    catch (...)
    {
        std::cerr << "str2int error\n" << std::endl;
        return 0;
    }
}

int CLogger::base64_encode(char* out, char* in, int size)
{
    int loop, total;
    char* translate;

    total = size / 3 * 4 + ((size % 3) ? 4 : 0);
    if (out == NULL || in == NULL)
        return total;

    translate = out;
    for (loop = 0; loop + 3 <= size; loop += 3, in += 3, out += 4)
    {
        out[0] = (in[0] & 0xFC) >> 2;
        out[1] = ((in[0] & 0x03) << 4) | ((in[1] & 0xF0) >> 4);
        out[2] = ((in[1] & 0x0F) << 2) | ((in[2] & 0xC0) >> 6);
        out[3] = in[2] & 0x3F;
    }

    switch (size %= 3)
    {
    case 0:
        break;
    case 1:
        out[0] = (in[0] & 0xFC) >> 2;
        out[1] = (in[0] & 0x03) << 4;
        out[2] = 65;
        out[3] = 65;
        break;
    case 2:
        out[0] = (in[0] & 0xFC) >> 2;
        out[1] = ((in[0] & 0x03) << 4) | ((in[1] & 0xF0) >> 4);
        out[2] = (in[1] & 0x0F) << 2;
        out[3] = 65;
        break;
    default:
        break;
    }

    for (loop = 0, out = translate; loop < total; loop++, ++out)
    {
        if (*out < 26)
            *out += 'A';
        else if (*out < 52)
            *out += 'a' - 26;
        else if (*out < 62)
            *out += '0' - 52;
        else if (*out == 62)
            *out = '+';
        else if (*out == 63)
            *out = '/';
        else
            *out = '=';
    }

    return total;
}

int CLogger::base64_decode(char* out, char* in, int size)
{
    char code = 0, code1 = 0, code2 = 0, code3 = 0;
    int i, count, loop, bytes;

    for (loop = 0, count = 0, bytes = 0; loop < size; loop++)
    {
        code = (unsigned char)*in++;
        if ('A' <= code && code <= 'Z')
            code -= 'A';
        else if ('a' <= code && code <= 'z')
        {
            code -= 'a';
            code += 26;
        }
        else if ('0' <= code && code <= '9')
        {
            code -= '0';
            code += 52;
        }
        else if (code == '+')
            code = 62;
        else if (code == '/')
            code = 63;
        else if (code == '=' && size - loop <= 2)
            break;
        else
            continue;

        switch (i = count % 4)
        {
        case 0:
            if (count > 0)
            {
                *out++ = code1;
                *out++ = code2;
                *out++ = code3;
                bytes += 3;
            }
            code1 = code << 2;
            break;
        case 1:
            code1 |= (code & 0x30) >> 4;
            code2 = (code & 0x0F) << 4;
            break;
        case 2:
            code2 |= (code & 0x3C) >> 2;
            code3 = (code & 0x03) << 6;
            break;
        case 3:
        default:
            code3 |= code;
            break;
        }

        ++count;
    }

    if (count != 0)
    {
        *out++ = code1;
        ++bytes;
        size -= loop;
        if (size <= 1)
        {
            *out++ = code2;
            ++bytes;
        }
        if (size == 0)
        {
            *out = code3;
            ++bytes;
        }
    }

    return bytes;
}

int CLogger::shmapiInit()
{
    int iret = 0;
    HSM_MSGID_ST stMsg;
    memset(&stMsg, 0, sizeof(stMsg));
    iret = shmapiCreateQueue(&stMsg.iMsgIDLog, g_msgkey);
    if (iret != 0)
    {
        perror("shmapiInit failed.\n");
        return -1;
    }
    if (gpstMsg)
    {
        memcpy(gpstMsg, &stMsg, sizeof(stMsg));
    }
    return iret;
}

int CLogger::shmapiCreateQueue(unsigned int* uimsgId, unsigned int msgKey)
{
    int istatus = 0;
    // 创建消息队列
    if ((istatus = msgget(msgKey, IPC_CREAT | 0666)) == -1)
    {
        perror("shmapiCreateQueue failed.\n");
        return -1;
    }
    *uimsgId = istatus;
    return 0;
}

int CLogger::shmapiSendToMsg(unsigned int imsg_id, unsigned char* ucdata, int ilen, long lmsgtype)
{
    if (ilen > LOG_MSG_SIZE)
        return (-1);

    if (msgsnd(imsg_id, (void*)ucdata, ilen, 0) < 0)
    {
        printf("msgsnd errno = %d, imsg_id = %d, ilen = %d\n", errno, imsg_id, ilen);
        return (-1);
    }
    return (0);
}

int CLogger::shmapiSendMsgLog(unsigned int log_msgid, unsigned char* ucdata, int ilen, long lmsgtype)
{
    int iret;
    if ((NULL == ucdata))
        return -1;

    iret = shmapiSendToMsg(log_msgid, ucdata, ilen, lmsgtype);
    return iret;
}

int CLogger::shmapiReceiveFromMsg(unsigned int imsg_id, unsigned char* ucdata, unsigned int idatasize, long lmsgtype,
                                  int iflag)
{
    int ilen;
    ilen = msgrcv(imsg_id, ucdata, idatasize, lmsgtype, iflag);
    if (ilen <= 0)
    {
        return (-3);
    }
    return ilen;
}

int CLogger::shmapiGetMsgLog(unsigned int log_msgid, unsigned char* ucdata, unsigned int idatasize, long lmsgtype)
{
    int iret;
    iret = shmapiReceiveFromMsg(log_msgid, ucdata, idatasize, lmsgtype, 0);
    return iret;
}

static unsigned char MSG_RCV_INFO_T[LOG_MSG_SIZE];
static unsigned char MSG_RCV_DEBUG_T[LOG_MSG_SIZE];
static unsigned char MSG_RCV_WARN_T[LOG_MSG_SIZE];
static unsigned char MSG_RCV_ERROR_T[LOG_MSG_SIZE];

void CLogger::logFileDeal(void)
{
    int rv;
    unsigned int i, j, z, k;
    unsigned int info_t, dug_t, warn_t, err_t, len;
    MYMSG_ST msg_rcv;

    while (1)
    {
        for (info_t = 0, dug_t = 0, warn_t = 0, err_t = 0,
             i = 0, j = 0, z = 0, k = 0;
             i < MAX_MSG_SIZE_PRE && j < MAX_MSG_SIZE_PRE &&
             z < MAX_MSG_SIZE_PRE && k < MAX_MSG_SIZE_PRE;)
        {
            rv = shmapiGetMsgLog(gpstMsg->iMsgIDLog, (unsigned char*)&msg_rcv, sizeof(MYMSG_ST) - sizeof(long), 0);
            if (rv > 0)
            {
                len = msg_rcv.mtext[1] * 256 + msg_rcv.mtext[2];
                if (len <= 0 || len >= 4096 + 1)
                {
                    break;
                }
                if (msg_rcv.mtext[0] == LOG_LEVEL_INFO)
                {
                    i++;
                    memcpy(MSG_RCV_INFO_T + info_t, msg_rcv.mtext + 3, len);
                    info_t += len;
                }
                else if (msg_rcv.mtext[0] == LOG_LEVEL_DEBUG)
                {
                    j++;
                    memcpy(MSG_RCV_DEBUG_T + dug_t, msg_rcv.mtext + 3, len);
                    dug_t += len;
                }
                else if (msg_rcv.mtext[0] == LOG_LEVEL_WARN)
                {
                    z++;
                    memcpy(MSG_RCV_WARN_T + warn_t, msg_rcv.mtext + 3, len);
                    warn_t += len;
                }
                else if (msg_rcv.mtext[0] == LOG_LEVEL_ERROR)
                {
                    k++;
                    memcpy(MSG_RCV_ERROR_T + err_t, msg_rcv.mtext + 3, len);
                    err_t += len;
                }
                break;
            }
            else /*cannot receive msg*/
            {
                sleep(1);
                break;
            }
        }

        if (i > 0)
        {
            logWriteLog(LOG_LEVEL_NONE, MSG_RCV_INFO_T, info_t);
            logWriteLog(LOG_LEVEL_INFO, MSG_RCV_INFO_T, info_t);
            if (g_syslog > 0)
            {
                syslog(LOG_SYSLOG | LOG_INFO, "%s", MSG_RCV_INFO_T);
            }
        }

        if (j > 0)
        {
            logWriteLog(LOG_LEVEL_NONE, MSG_RCV_DEBUG_T, dug_t);
            logWriteLog(LOG_LEVEL_DEBUG, MSG_RCV_DEBUG_T, dug_t);
            if (g_syslog > 0)
            {
                syslog(LOG_SYSLOG | LOG_DEBUG, "%s", MSG_RCV_DEBUG_T);
            }
        }
        if (z > 0)
        {
            logWriteLog(LOG_LEVEL_NONE, MSG_RCV_WARN_T, warn_t);
            logWriteLog(LOG_LEVEL_WARN, MSG_RCV_WARN_T, warn_t);
            if (g_syslog > 0)
            {
                syslog(LOG_SYSLOG | LOG_WARNING, "%s", MSG_RCV_WARN_T);
            }
        }

        if (k > 0)
        {
            logWriteLog(LOG_LEVEL_NONE, MSG_RCV_ERROR_T, err_t);
            logWriteLog(LOG_LEVEL_ERROR, MSG_RCV_ERROR_T, err_t);
            if (g_syslog > 0)
            {
                syslog(LOG_SYSLOG | LOG_ERR, "%s", MSG_RCV_ERROR_T);
            }
        }
    }
    printf("\n LogFileDeal end \n");
}

int CLogger::logStartProcess(void)
{
    logFileDeal();
    return 0;
}

void CLogger::logProcess()
{
    int iret = -1;
    iret = logStartProcess();
    if (iret == -1)
    {
        printf("log start process error \n");
    }
    return;
}

char* CLogger::getLogTime(void)
{
    static char buff[64] = {0};
    time_t ltime;
    struct tm* today;
    time(&ltime);

    today = localtime(&ltime);
    sprintf(buff, "%4d-%02d-%02d %02d:%02d:%02d",
            (today->tm_year + 1900),
            (today->tm_mon + 1),
            today->tm_mday,
            today->tm_hour,
            today->tm_min,
            today->tm_sec);
    return buff;
}

int CLogger::getLogFileName(int ni_Type, char* path, void* pv_Name)
{
    time_t ltime;
    struct tm* st_TM;
    char datetime[32] = {0};
    time(&ltime);
    st_TM = localtime(&ltime);

    sprintf(datetime, "%04d-%02d-%02d", st_TM->tm_year + 1900, st_TM->tm_mon + 1, st_TM->tm_mday);

    if (ni_Type == LOG_LEVEL_INFO)
        sprintf((char*)pv_Name, "%s/info.%s.%s.log",
                path,
                m_serviceName.c_str(),
                datetime);
    else if (ni_Type == LOG_LEVEL_DEBUG)
        sprintf((char*)pv_Name, "%s/debug.%s.%s.log",
                path,
                m_serviceName.c_str(),
                datetime);
    else if (ni_Type == LOG_LEVEL_WARN)
        sprintf((char*)pv_Name, "%s/warn.%s.%s.log",
                path,
                m_serviceName.c_str(),
                datetime);
    else if (ni_Type == LOG_LEVEL_ERROR)
        sprintf((char*)pv_Name, "%s/error.%s.%s.log",
                path,
                m_serviceName.c_str(),
                datetime);
    else if (ni_Type == LOG_LEVEL_MNG_T)
        sprintf((char*)pv_Name, "%s/info.%s.%s.log",
                path,
                "sdfmng",
                datetime);
    else if (ni_Type == LOG_LEVEL_MNG_E)
        sprintf((char*)pv_Name, "%s/error.%s.%s.log",
                path,
                "sdfmng",
                datetime);
    else if (ni_Type == LOG_LEVEL_NONE)
        sprintf((char*)pv_Name, "%s/all.%s.%s.log",
                path,
                m_serviceName.c_str(),
                datetime);
    else
        sprintf((char*)pv_Name, "%s/all.%s.%s.log",
                path,
                m_serviceName.c_str(),
                datetime);
    return 0;
}

int CLogger::logWriteLog(int type, void* pv_Msg, int ni_MsgLen)
{
    int ni_FD, ni_WriteLen = 0;
    unsigned char auc_LogName[512];
    unsigned char datatime[128];
    unsigned char path[256];
    //unsigned char tmp[128];
    //time_t ltime;
    //struct tm *tm_time = NULL;

    memset(auc_LogName, 0, sizeof(auc_LogName));
    //memset(datatime,0,sizeof(datatime));
    //memset(path,0,sizeof(path));
    //time(&ltime);
    //tm_time = localtime(&ltime);
    //sprintf((char *)datatime,"%04d%02d%02d",tm_time->tm_year+1900,
    //        tm_time->tm_mon+1,
    //        tm_time->tm_mday);

    if (type == LOG_LEVEL_NONE)
    {
        sprintf((char*)path, LOG_FILE_PATH_ALL, (char*)m_productName.c_str());
        //sprintf((char *)path, "%s%s", tmp, (char *)datatime);
    }
    else if (type == LOG_LEVEL_INFO)
    {
        sprintf((char*)path, LOG_FILE_PATH_INFO, (char*)m_productName.c_str());
        //sprintf((char *)path, "%s%s", tmp, (char *)datatime);
    }
    else if (type == LOG_LEVEL_DEBUG)
    {
        sprintf((char*)path, LOG_FILE_PATH_DEBUG, (char*)m_productName.c_str());
        //sprintf((char *)path, "%s%s", tmp, (char *)datatime);
    }
    else if (type == LOG_LEVEL_WARN)
    {
        sprintf((char*)path, LOG_FILE_PATH_WARN, (char*)m_productName.c_str());
        //sprintf((char *)path, "%s%s", tmp, (char *)datatime);
    }
    else
    {
        sprintf((char*)path, LOG_FILE_PATH_ERROR, (char*)m_productName.c_str());
        //sprintf((char *)path, "%s%s", tmp, (char *)datatime);
    }
    if (access((char*)path, 0) == -1)
    {
        if (mkdir((char*)path, 0777))
        {
            printf("\n mkdir path = %s error\n", path);
            return -1;
        }
    }

    getLogFileName(type, (char*)path, auc_LogName);
    // printf("logWriteLog type = %d, auc_LogName = %s, ni_WriteLen = %d, ni_MsgLen = %d\n", type, auc_LogName, ni_WriteLen, ni_MsgLen);

    if ('\0' == auc_LogName[0])
        return -3;
    ni_FD = open((char*)auc_LogName, O_WRONLY | O_CREAT | O_APPEND, S_IRWXU);
    if (ni_FD < 0)
    {
        return -4;
    }

    ni_WriteLen = write(ni_FD, pv_Msg, ni_MsgLen);
    if (ni_WriteLen < ni_MsgLen)
    {
        close(ni_FD);
        return -5;
    }
    close(ni_FD);
    //printf("logWriteLog write ni_WriteLen = %d\n", ni_WriteLen);

    return 0;
}

int CLogger::fileRead(char* filename, char* mode, unsigned char* buffer, size_t size)
{
    FILE* fp = NULL;
    size_t rw, rwed;
    if ((fp = fopen(filename, mode)) == NULL)
    {
        return -1;
    }
    rwed = 0;

    while ((!feof(fp)) && (size > rwed))
    {
        if ((rw = fread(buffer + rwed, 1, size - rwed, fp)) <= 0)
        {
            break;
        }
        rwed += rw;
    }
    fclose(fp);
    return (int)rwed;
}

int CLogger::getConfigByKeyWord(char* keyword, char* keyvalue)
{
    unsigned char buffer[1024];
    memset(buffer, 0x00, sizeof(buffer));
    int ret = fileRead((char*)LOG_CONFIG_FILE, (char*)"rb+", buffer, sizeof(buffer));
    if (ret == -1)
    {
        return -100;
    }
    int i, j, keywordlen;
    keywordlen = strlen(keyword);
    for (i = 0; i < (int)strlen((char*)buffer); i++)
    {
        if (strncmp(keyword, (char*)(buffer + i), keywordlen) == 0)
        {
            for (j = i + keywordlen; j < (int)strlen((char*)buffer); j++)
            {
                if (buffer[j] == '=')
                {
                    strcpy(keyvalue, (char*)buffer + j + 1);
                    return 0;
                }
            }
        }
    }
    return -1;
}

void CLogger::threadLogFunc()
{
    char name[16] = {0};
    sprintf(name, "file_log");
    int ret = prctl(PR_SET_NAME, (unsigned long)name, NULL, NULL, NULL);
    if (ret < 0)
    {
        printf("[file_log_func:prctl PR_SET_NAME fail!]\n");
        return;
    }
    logProcess();
    return;
}

void CLogger::threadTimerFunc()
{
    int isSysLog = 0;
    int iLogLevel = 0;
    int iLogSize = 0;
    char tmp[16] = {0};
    char name[16] = {0};
    char logConf[128] = {0};
    sprintf(name, "log_timer");
    int ret = prctl(PR_SET_NAME, (unsigned long)name, NULL, NULL, NULL);
    if (ret < 0)
    {
        printf("[log_timer_func:prctl PR_SET_NAME fail!]\n");
        return;
    }
    //60 second = 1 minute
    while (1)
    {
        memset(tmp, 0x00, sizeof(tmp));
        ret = getConfigByKeyWord((char*)"LogLevel", tmp);
        if (ret == 0)
        {
            g_loglevel = str2int(tmp);
        }
        else
        {
            g_loglevel = LOG_LEVEL_INFO | LOG_LEVEL_WARN | LOG_LEVEL_ERROR;
        }
        // printf("===>>> g_loglevel = %d\n", g_loglevel);

        memset(tmp, 0x00, sizeof(tmp));
        ret = getConfigByKeyWord((char*)"isSysLog", tmp);
        if (ret == 0)
        {
            g_syslog = str2int(tmp);
        }
        else
        {
            g_syslog = 0;
        }
        // printf("===>>> g_syslog = %d\n", g_syslog);

        memset(tmp, 0x00, sizeof(tmp));
        ret = getConfigByKeyWord((char*)"LogSplit", tmp);
        if (ret == 0)
        {
            g_logsplit = str2int(tmp);
        }
        else
        {
            g_logsplit = 0;
        }
        // printf("===>>> g_logsplit = %d\n", g_logsplit);

        memset(tmp, 0x00, sizeof(tmp));
        ret = getConfigByKeyWord((char*)"LogSavingDays", tmp);
        if (ret == 0)
        {
            g_logSavingDays = str2int(tmp);
        }
        else
        {
            g_logSavingDays = 0;
        }
        // printf("===>>> g_logSavingDays = %d\n", g_logSavingDays);

        snprintf(logConf, 127, "logLevel: %d, isSysLog: %d, logSplit: %d, logSavingDays: %d", g_loglevel, g_syslog,
                 g_logsplit, g_logSavingDays);
        if (m_logconf.compare(logConf) != 0)
        {
            m_logconf = logConf;
            info("%s\n", logConf);
        }

        if ((g_logSavingDays > 0) & (g_logSavingDays < 365))
        {
            cleanLogFile();
        }
        sleep(60); //60 second;
    }
}

void CLogger::joinThread()
{
    if (g_threadLog && g_threadLog->joinable())
    {
        // g_threadLog->join();
        g_threadLog->detach();
    }
    if (g_threadTimer && g_threadTimer->joinable())
    {
        // g_threadTimer->join();
        g_threadTimer->detach();
    }
}

void CLogger::setStdoutEnable(bool enable)
{
    g_stdoutEnable = enable;
}
