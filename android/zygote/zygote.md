zygote

入口文件app_main.cpp，

```c++
int main(int argc, char* const argv[])
{
  .......
    if (zygote) {
        runtime.start("com.android.internal.os.ZygoteInit", args, zygote);
    } else if (className) {
        runtime.start("com.android.internal.os.RuntimeInit", args, zygote);
    } else {
        fprintf(stderr, "Error: no class name or --zygote supplied.\n");
        app_usage();
        LOG_ALWAYS_FATAL("app_process: no class name or --zygote supplied.");
    }
}
```

runtime为AppRuntime类，继承自AndroidRuntime.cpp，这里的start方法调用的就是AndroidRuntime类方法

```c++
/*
 * Start the Android runtime.  This involves starting the virtual machine
 * and calling the "static void main(String[] args)" method in the class
 * named by "className".
 *
 * Passes the main function two arguments, the class name and the specified
 * options string.
 */
void AndroidRuntime::start(const char* className, const Vector<String8>& options, bool zygote)
{
  .......
    /* start the virtual machine */
    JniInvocation jni_invocation;
    jni_invocation.Init(NULL);
    JNIEnv* env;
   // 开启Dalvik虚拟机
    if (startVm(&mJavaVM, &env, zygote) != 0) {
        return;
    }
  // 设置相关vm参数
    onVmCreated(env);

    /*
     * Register android functions.
     */
    if (startReg(env) < 0) {
        ALOGE("Unable to register all android natives\n");
        return;
    }
	..........
    /*
     * Start VM.  This thread becomes the main thread of the VM, and will
     * not return until the VM exits.
     */
    char* slashClassName = toSlashClassName(className != NULL ? className : "");
    jclass startClass = env->FindClass(slashClassName);
    if (startClass == NULL) {
        ALOGE("JavaVM unable to locate class '%s'\n", slashClassName);
        /* keep going */
    } else {
        jmethodID startMeth = env->GetStaticMethodID(startClass, "main",
            "([Ljava/lang/String;)V");
        if (startMeth == NULL) {
            ALOGE("JavaVM unable to find main() in '%s'\n", className);
            /* keep going */
        } else {
            env->CallStaticVoidMethod(startClass, startMeth, strArray);

#if 0
            if (env->ExceptionCheck())
                threadExitUncaughtException(env);
#endif
        }
    }
    free(slashClassName);

    ALOGD("Shutting down VM\n");
    if (mJavaVM->DetachCurrentThread() != JNI_OK)
        ALOGW("Warning: unable to detach main thread\n");
    if (mJavaVM->DestroyJavaVM() != 0)
        ALOGW("Warning: VM did not shut down cleanly\n");
}
```

```c++

    public static void main(String argv[]) {
        ZygoteServer zygoteServer = new ZygoteServer();

        // Mark zygote start. This ensures that thread creation will throw
        // an error.
        ZygoteHooks.startZygoteNoThreadCreation();

        // Zygote goes into its own process group.
        try {
            Os.setpgid(0, 0);
        } catch (ErrnoException ex) {
            throw new RuntimeException("Failed to setpgid(0,0)", ex);
        }

        final Runnable caller;
        try {
            // Report Zygote start time to tron unless it is a runtime restart
            if (!"1".equals(SystemProperties.get("sys.boot_completed"))) {
                MetricsLogger.histogram(null, "boot_zygote_init",
                        (int) SystemClock.elapsedRealtime());
            }

            String bootTimeTag = Process.is64Bit() ? "Zygote64Timing" : "Zygote32Timing";
            TimingsTraceLog bootTimingsTraceLog = new TimingsTraceLog(bootTimeTag,
                    Trace.TRACE_TAG_DALVIK);
            bootTimingsTraceLog.traceBegin("ZygoteInit");
            RuntimeInit.enableDdms();

            boolean startSystemServer = false;
            String socketName = "zygote";
            String abiList = null;
            boolean enableLazyPreload = false;
            for (int i = 1; i < argv.length; i++) {
                if ("start-system-server".equals(argv[i])) {
                    startSystemServer = true;
                } else if ("--enable-lazy-preload".equals(argv[i])) {
                    enableLazyPreload = true;
                } else if (argv[i].startsWith(ABI_LIST_ARG)) {
                    abiList = argv[i].substring(ABI_LIST_ARG.length());
                } else if (argv[i].startsWith(SOCKET_NAME_ARG)) {
                    socketName = argv[i].substring(SOCKET_NAME_ARG.length());
                } else {
                    throw new RuntimeException("Unknown command line argument: " + argv[i]);
                }
            }

            if (abiList == null) {
                throw new RuntimeException("No ABI list supplied.");
            }
						// 这里注册服务，实际是开启本地服务，通过绑定文件描述对应的fd的socket实现
            zygoteServer.registerServerSocketFromEnv(socketName);
            // In some configurations, we avoid preloading resources and classes eagerly.
            // In such cases, we will preload things prior to our first fork.
            if (!enableLazyPreload) {
                bootTimingsTraceLog.traceBegin("ZygotePreload");
                EventLog.writeEvent(LOG_BOOT_PROGRESS_PRELOAD_START,
                    SystemClock.uptimeMillis());
                preload(bootTimingsTraceLog);
                EventLog.writeEvent(LOG_BOOT_PROGRESS_PRELOAD_END,
                    SystemClock.uptimeMillis());
                bootTimingsTraceLog.traceEnd(); // ZygotePreload
            } else {
                Zygote.resetNicePriority();
            }

            // Do an initial gc to clean up after startup
            bootTimingsTraceLog.traceBegin("PostZygoteInitGC");
          // 运行几个特殊的GC，以尝试清除几代softly和final-reachable的对象以及任何其他垃圾。 
          // 这仅在fork（）之前有用。
            gcAndFinalize();
            bootTimingsTraceLog.traceEnd(); // PostZygoteInitGC

            bootTimingsTraceLog.traceEnd(); // ZygoteInit
            // Disable tracing so that forked processes do not inherit stale tracing tags from
            // Zygote.
            Trace.setTracingEnabled(false, 0);
						// 设置安全保障：
            Zygote.nativeSecurityInit();

            // Zygote process unmounts root storage spaces.
            Zygote.nativeUnmountStorageOnInit();
						// 它标志着可以重新启动线程（例如重新启动守护程序）的时间点。
            ZygoteHooks.stopZygoteNoThreadCreation();

            if (startSystemServer) {
                Runnable r = forkSystemServer(abiList, socketName, zygoteServer);

                // {@code r == null} in the parent (zygote) process, and {@code r != null} in the
                // child (system_server) process.
                if (r != null) {
                    r.run();
                    return;
                }
            }

            Log.i(TAG, "Accepting command socket connections");

            // The select loop returns early in the child process after a fork and
            // loops forever in the zygote.
            caller = zygoteServer.runSelectLoop(abiList);
        } catch (Throwable ex) {
            Log.e(TAG, "System zygote died with exception", ex);
            throw ex;
        } finally {
            zygoteServer.closeServerSocket();
        }

        // We're in the child process and have exited the select loop. Proceed to execute the
        // command.
        if (caller != null) {
            caller.run();
        }
    }
```

这里在详细看下forkSystemServer方法

```c++
    /**
     * Prepare the arguments and forks for the system server process.
     *
     * Returns an {@code Runnable} that provides an entrypoint into system_server code in the
     * child process, and {@code null} in the parent.
     */
    private static Runnable forkSystemServer(String abiList, String socketName,
            ZygoteServer zygoteServer) {
        long capabilities = posixCapabilitiesAsBits(
            OsConstants.CAP_IPC_LOCK,
            OsConstants.CAP_KILL,
            OsConstants.CAP_NET_ADMIN,
            OsConstants.CAP_NET_BIND_SERVICE,
            OsConstants.CAP_NET_BROADCAST,
            OsConstants.CAP_NET_RAW,
            OsConstants.CAP_SYS_MODULE,
            OsConstants.CAP_SYS_NICE,
            OsConstants.CAP_SYS_PTRACE,
            OsConstants.CAP_SYS_TIME,
            OsConstants.CAP_SYS_TTY_CONFIG,
            OsConstants.CAP_WAKE_ALARM,
            OsConstants.CAP_BLOCK_SUSPEND
        );
        /* Containers run without some capabilities, so drop any caps that are not available. */
        StructCapUserHeader header = new StructCapUserHeader(
                OsConstants._LINUX_CAPABILITY_VERSION_3, 0);
        StructCapUserData[] data;
        try {
            data = Os.capget(header);
        } catch (ErrnoException ex) {
            throw new RuntimeException("Failed to capget()", ex);
        }
        capabilities &= ((long) data[0].effective) | (((long) data[1].effective) << 32);

        /* Hardcoded command line to start the system server */
        String args[] = {
            "--setuid=1000",
            "--setgid=1000",
            "--setgroups=1001,1002,1003,1004,1005,1006,1007,1008,1009,1010,1018,1021,1023,1024,1032,1065,3001,3002,3003,3006,3007,3009,3010",
            "--capabilities=" + capabilities + "," + capabilities,
            "--nice-name=system_server",
            "--runtime-args",
            "--target-sdk-version=" + VMRuntime.SDK_VERSION_CUR_DEVELOPMENT,
            "com.android.server.SystemServer",
        };
        ZygoteConnection.Arguments parsedArgs = null;

        int pid;

        try {
            parsedArgs = new ZygoteConnection.Arguments(args);
            ZygoteConnection.applyDebuggerSystemProperty(parsedArgs);
            ZygoteConnection.applyInvokeWithSystemProperty(parsedArgs);

            boolean profileSystemServer = SystemProperties.getBoolean(
                    "dalvik.vm.profilesystemserver", false);
            if (profileSystemServer) {
                parsedArgs.runtimeFlags |= Zygote.PROFILE_SYSTEM_SERVER;
            }

            /* Request to fork the system server process */
            pid = Zygote.forkSystemServer(
                    parsedArgs.uid, parsedArgs.gid,
                    parsedArgs.gids,
                    parsedArgs.runtimeFlags,
                    null,
                    parsedArgs.permittedCapabilities,
                    parsedArgs.effectiveCapabilities);
        } catch (IllegalArgumentException ex) {
            throw new RuntimeException(ex);
        }

        /* For child process */
        if (pid == 0) {
            if (hasSecondZygote(abiList)) {
                waitForSecondaryZygote(socketName);
            }

            zygoteServer.closeServerSocket();
            return handleSystemServerProcess(parsedArgs);
        }

        return null;
    }
```

ZygoteConnection用来发送请求，这里最终调用Zygote类fork子进程

```c++
    /**
     * Special method to start the system server process. In addition to the
     * common actions performed in forkAndSpecialize, the pid of the child
     * process is recorded such that the death of the child process will cause
     * zygote to exit.
     *
     * @param uid the UNIX uid that the new process should setuid() to after
     * fork()ing and and before spawning any threads.
     * @param gid the UNIX gid that the new process should setgid() to after
     * fork()ing and and before spawning any threads.
     * @param gids null-ok; a list of UNIX gids that the new process should
     * setgroups() to after fork and before spawning any threads.
     * @param runtimeFlags bit flags that enable ART features.
     * @param rlimits null-ok an array of rlimit tuples, with the second
     * dimension having a length of 3 and representing
     * (resource, rlim_cur, rlim_max). These are set via the posix
     * setrlimit(2) call.
     * @param permittedCapabilities argument for setcap()
     * @param effectiveCapabilities argument for setcap()
     *
     * @return 0 if this is the child, pid of the child
     * if this is the parent, or -1 on error.
     */
    public static int forkSystemServer(int uid, int gid, int[] gids, int runtimeFlags,
            int[][] rlimits, long permittedCapabilities, long effectiveCapabilities) {
        VM_HOOKS.preFork();
        // Resets nice priority for zygote process.
        resetNicePriority();
        int pid = nativeForkSystemServer(
                uid, gid, gids, runtimeFlags, rlimits, permittedCapabilities, effectiveCapabilities);
        // Enable tracing as soon as we enter the system_server.
        if (pid == 0) {
            Trace.setTracingEnabled(true, runtimeFlags);
        }
        VM_HOOKS.postForkCommon();
        return pid;
    }
```

VM_HOOKS.preFork方法，最终会调用底层的art/runtime/gc/heap.cc Heap::PreZygoteFork()方法进行内存释放并整理，以便腾出更多空间来fork下个进程