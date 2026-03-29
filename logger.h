#ifndef _CLOGGER_H_
#define _CLOGGER_H_

#include <iostream>
#include <thread>
#include <memory>
#include <mutex>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>


// 日志级别定义(异步)
#define LOG_LEVEL_INFO          0x01
#define LOG_LEVEL_DEBUG         0x02
#define LOG_LEVEL_WARN          0x04
#define LOG_LEVEL_ERROR         0x08
// 管理日志定义(同步)
#define LOG_LEVEL_MNG_T         0x10
#define LOG_LEVEL_MNG_E         0x20

class CLogger
{
public:
	CLogger();
	~CLogger();

public:
    int initCLogger(const std::string& productName, const std::string& serviceName);
    // 异步日志写入()
    int asyncLogWrite(int type,char *file,int line,char* ip, const char *fmt, ...);
    // 同步日志写入()
    int syncLogwrite(int type,char *file,int line,char* ip, const char *fmt,...);

    // 
    static CLogger* getInstance(const std::string& productName = "sslvpn", const std::string& serviceName = "sslvpn-server", bool daemon = false);

    // sslvpn服务端输出日志调用
    void debug(const char *fmt, ...);
    void info(const char *fmt, ...);
    void warn(const char* fmt, ...);
    void error(const char* fmt, ...); 

protected:
    bool createDirectory(const std::string& dirPath);
    bool shmapiGetShm();
    bool deleteLogFile(std::string file);
    bool cleanLogFile();  // 日志清理
    unsigned char calcCRC(char *strData, int len);
    int str2int(std::string str);   // 字符串转int
    

    int base64_encode(char *out, char *in, int size);
    int base64_decode(char *out, char *in, int size);

    int shmapiInit();
    int shmapiCreateQueue(unsigned int *uimsgId, unsigned int msgKey);
    int shmapiSendToMsg(unsigned int imsg_id, unsigned char *ucdata, int ilen, long lmsgtype);
    int shmapiSendMsgLog(unsigned int log_msgid, unsigned char *ucdata, int ilen, long lmsgtype);
    int shmapiReceiveFromMsg(unsigned int imsg_id, unsigned char *ucdata, unsigned int idatasize, long lmsgtype, int iflag);
    int shmapiGetMsgLog(unsigned int log_msgid, unsigned char *ucdata, unsigned int idatasize, long lmsgtype);

    void logFileDeal(void);
    int  logStartProcess(void);
    void logProcess();

    char *getLogTime(void); 

    int  getLogFileName(int ni_Type, char *path,void *pv_Name);
    int  logWriteLog(int type, void *pv_Msg, int ni_MsgLen);

    int fileRead(char *filename, char *mode, unsigned char *buffer, size_t size);
    int getConfigByKeyWord(char *keyword, char *keyvalue);
    void threadLogFunc();
    void threadTimerFunc();

    void joinThread();
    void setStdoutEnable(bool enable);
    

private:
    // 日志锁
    std::mutex log_mutex;
    //
    std::string m_productName;
    std::string m_serviceName;
    // 记录删除日志时间
    std::string m_recordDelLogTime; 
    std::string m_recordDelAllLogTime;
    // 是否输出到终端显示
    bool g_stdoutEnable;
    // 
    static CLogger* instance;
    // 线程
    std::shared_ptr<std::thread> g_threadLog;
    std::shared_ptr<std::thread> g_threadTimer;

    int g_msgkey; 
    int g_syslog;
    int g_logsize;
    int g_logsplit;
    int g_loglevel;         // 日志输出级别设置
    int g_logSavingDays;    // 日志保留天数设置
    int g_logCleanTotalDays;// 日志清理总天数设置

    std::string m_logconf;  // 日志配置
};

static CLogger* log() {
    return CLogger::getInstance();
}

static const char* my_basename(const char* path) {
    const char* base = strrchr(path, '/');
    return base ? base+1 : path;
}
#define __FILENAME__ my_basename(__FILE__)
#define LOG_DEBUG(fmt, ...) log()->debug("[%s:%d] " fmt, __FILENAME__,  __LINE__,  ##__VA_ARGS__);
#define LOG_INFO(fmt, ...) log()->info("[%s:%d] " fmt, __FILENAME__,  __LINE__,  ##__VA_ARGS__);
#define LOG_WARN(fmt, ...) log()->warn("[%s:%d] " fmt, __FILENAME__,  __LINE__,  ##__VA_ARGS__);
#define LOG_ERROR(fmt, ...) log()->error("[%s:%d] " fmt, __FILENAME__, __LINE__,  ##__VA_ARGS__);

#endif // _CLOGGER_H_

