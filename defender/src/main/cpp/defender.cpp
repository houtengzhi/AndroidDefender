#include <jni.h>
#include <string>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <android/log.h>
#include <pthread.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "syscall_arch.h"
#include "syscalls.h"
#include "mylibc.h"
#include "android_log.h"


#define TAG "DefenderLib"
#define MAX_LENGTH 256

static const char *PROC_STATUS = "/proc/self/task/%s/status";
static const char *PROC_FD = "/proc/self/fd";
static const char *PROC_TASK = "/proc/self/task";
static const char *FRIDA_THREAD_GUM_JS_LOOP = "gum-js-loop";
static const char *FRIDA_THREAD_GMAIN = "gmain";
static const char *FRIDA_NAMEDPIPE_LINJECTOR = "linjector";

void* detect_frida(void *p);

bool detect_frida_server();

static inline ssize_t read_one_line(int fd, char *buf, unsigned int max_len);

static inline bool detect_frida_threads();

static inline bool detect_frida_namedpipe();

static inline void detect_frida_memdiskcompare();


void* detect_frida(void *p) {
    bool detected = false;
    detected = detect_frida_threads() || detect_frida_namedpipe() || detect_frida_server();
    pthread_exit((void *)detected);
}

bool detect_frida_server() {
    LOGD(TAG, "detect_frida_server()");
    bool detected = false;
    struct sockaddr_in sa{};
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_aton("127.0.0.1", &(sa.sin_addr));

    int sock;
    char res[7];
    int ret;
    int i;

    for(i = 0 ; i <= 65535 ; i++) {

        sock = socket(AF_INET , SOCK_STREAM , 0);
        sa.sin_port = htons(i);

        if (connect(sock , (struct sockaddr*)&sa , sizeof sa) != -1) {
            memset(res, 0 , 7);

            send(sock, "\x00", 1, NULL);
            send(sock, "AUTH\r\n", 6, NULL);

            usleep(100); // Give it some time to answer

            if ((ret = recv(sock, res, 6, MSG_DONTWAIT)) != -1) {
                if (strcmp(res, "REJECT") == 0) {
                    LOGW(TAG, "FRIDA DETECTED - frida server running on port %d!", i);
                    detected = true;
                    break;
                }
            }
        }

        close(sock);
    }
    return detected;
}

__attribute__((always_inline))
static inline bool detect_frida_threads() {
    LOGD(TAG, "detect_frida_threads()");
    DIR *dir = opendir(PROC_TASK);
    bool detected = false;

    if (dir != NULL) {
        struct dirent *entry = NULL;
        while ((entry = readdir(dir)) != NULL) {
            char filePath[MAX_LENGTH] = "";

            if (0 == my_strcmp(entry->d_name, ".") || 0 == my_strcmp(entry->d_name, "..")) {
                continue;
            }
            snprintf(filePath, sizeof(filePath), PROC_STATUS, entry->d_name);

            int fd = my_openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);
            if (fd != 0) {
                char buf[MAX_LENGTH] = "";
                read_one_line(fd, buf, MAX_LENGTH);
                if (my_strstr(buf, FRIDA_THREAD_GUM_JS_LOOP) ||
                    my_strstr(buf, FRIDA_THREAD_GMAIN)) {
                    //Kill the thread. This freezes the app. Check if it is an anticpated behaviour
                    //int tid = my_atoi(entry->d_name);
                    //int ret = my_tgkill(getpid(), tid, SIGSTOP);
                    detected = true;
                    LOGW(TAG, "Frida specific thread found!");
                    break;
                }
                my_close(fd);
            }

        }
        closedir(dir);

    }
    return detected;

}

__attribute__((always_inline))
static inline bool detect_frida_namedpipe() {
    LOGD(TAG, "detect_frida_namedpipe()");
    DIR *dir = opendir(PROC_FD);
    bool detected = false;
    if (dir != NULL) {
        struct dirent *entry = NULL;
        while ((entry = readdir(dir)) != NULL) {
            struct stat filestat;
            char buf[MAX_LENGTH] = "";
            char filePath[MAX_LENGTH] = "";
            snprintf(filePath, sizeof(filePath), "/proc/self/fd/%s", entry->d_name);

            lstat(filePath, &filestat);

            if ((filestat.st_mode & S_IFMT) == S_IFLNK) {
                //TODO: Another way is to check if filepath belongs to a path not related to system or the app
                my_readlinkat(AT_FDCWD, filePath, buf, MAX_LENGTH);
                if (NULL != my_strstr(buf, FRIDA_NAMEDPIPE_LINJECTOR)) {
                    detected = true;
                    LOGW(TAG, "Frida specific named pipe found!");
                    break;
                }
            }

        }
    }
    closedir(dir);
    return detected;
}

__attribute__((always_inline))
static inline ssize_t read_one_line(int fd, char *buf, unsigned int max_len) {
    char b;
    ssize_t ret;
    ssize_t bytes_read = 0;

    my_memset(buf, 0, max_len);

    do {
        ret = my_read(fd, &b, 1);

        if (ret != 1) {
            if (bytes_read == 0) {
                // error or EOF
                return -1;
            } else {
                return bytes_read;
            }
        }

        if (b == '\n') {
            return bytes_read;
        }

        *(buf++) = b;
        bytes_read += 1;

    } while (bytes_read < max_len - 1);

    return bytes_read;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_moxo_defender_DefenderUtil_00024Companion_nativeDetectFrida(JNIEnv *env, jobject thiz,
                                                                     jobject callback) {
    pthread_t t;
    void * result;
    pthread_create(&t, nullptr, detect_frida, nullptr);
    pthread_join(t, &result);

    jclass javaClass = env->GetObjectClass(callback);
    if (javaClass == nullptr) {
        LOGW(TAG, "OnDetectFridaListener class is null.");
        return;
    }
    jmethodID jcallbackMethodId = env->GetMethodID(javaClass, "onDetected", "(Z)V");
    if (jcallbackMethodId == nullptr) {
        LOGW(TAG, "onDetected method is null.");
        return;
    }
    env->CallVoidMethod(callback, jcallbackMethodId, (bool)result);
}