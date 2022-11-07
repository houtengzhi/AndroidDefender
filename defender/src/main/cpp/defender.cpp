#include <jni.h>
#include <string>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <android/log.h>
#include <pthread.h>


#define APPNAME "MXDefender"

//int detect_frida(void *);

JavaVM *g_VM;

void* detect_frida(void *p) {

    JNIEnv *env = nullptr;
    bool needDetach = false;
    int getEnvStat = g_VM->GetEnv((void **)&env, JNI_VERSION_1_6);
    if (getEnvStat == JNI_EDETACHED) {
        if (g_VM->AttachCurrentThread(&env, nullptr) != 0) {
            return nullptr;
        }
        needDetach = true;
    }


    auto jcallback = (jobject)p;
    jclass javaClass = env->GetObjectClass(jcallback);
    if (javaClass == nullptr) {

    }
    jmethodID jcallbackMethodId = env->GetMethodID(javaClass, "onDetected", "(Z)V");
    if (jcallbackMethodId == nullptr) {

    }


    struct sockaddr_in sa{};
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_aton("127.0.0.1", &(sa.sin_addr));

    int sock;
    char res[7];
    int ret;
    int i;

    /*
         * 1: Frida Server Detection.
         */

    bool detected = false;
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
                    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME,  "FRIDA DETECTED [1] - frida server running on port %d!", i);
                    detected = true;
                    break;
                }
            }
        }

        close(sock);
    }
    env->CallVoidMethod(jcallback, jcallbackMethodId, detected);

    env->DeleteGlobalRef(jcallback);

    g_VM->DetachCurrentThread();
    return nullptr;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_moxo_defender_DefenderUtil_00024Companion_nativeDetectFrida(JNIEnv *env, jobject thiz,
                                                                     jobject listener) {
    (*env).GetJavaVM(&g_VM);
    jobject callback = env->NewGlobalRef(listener);

    pthread_t t;
    pthread_create(&t, nullptr, detect_frida, callback);
}