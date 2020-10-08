SystemServer

SystemServer是由Zygote fork出的一个进程，Zygote在forkSystemServer()方法中必须检查生成的SystemServer进程工作是否正常。而运行普通android应用程序时，只是负责创建应用程序进程，至于进程是否创建成功并不检查，而SystemServer会启动AMS等重要服务（不要跟ServiceManager搞混，SM管理进程服务，所有的binder需要注册到SM，也可以在SM中获取到）

并启动main方法

```c++
    /**
     * The main entry point from zygote.
     */
    public static void main(String[] args) {
        new SystemServer().run();
    }
```

```c++
frameworks/base/services/java/com/android/server/SystemServer.java
    private void run() {
        try {
            traceBeginAndSlog("InitBeforeStartServices");
            // If a device's clock is before 1970 (before 0), a lot of
            // APIs crash dealing with negative numbers, notably
            // java.io.File#setLastModified, so instead we fake it and
            // hope that time from cell towers or NTP fixes it shortly.
            if (System.currentTimeMillis() < EARLIEST_SUPPORTED_TIME) {
                Slog.w(TAG, "System clock is before 1970; setting to 1970.");
                SystemClock.setCurrentTimeMillis(EARLIEST_SUPPORTED_TIME);
            }

            //
            // Default the timezone property to GMT if not set.
            //
            String timezoneProperty =  SystemProperties.get("persist.sys.timezone");
            if (timezoneProperty == null || timezoneProperty.isEmpty()) {
                Slog.w(TAG, "Timezone not set; setting to GMT.");
                SystemProperties.set("persist.sys.timezone", "GMT");
            }

            // If the system has "persist.sys.language" and friends set, replace them with
            // "persist.sys.locale". Note that the default locale at this point is calculated
            // using the "-Duser.locale" command line flag. That flag is usually populated by
            // AndroidRuntime using the same set of system properties, but only the system_server
            // and system apps are allowed to set them.
            //
            // NOTE: Most changes made here will need an equivalent change to
            // core/jni/AndroidRuntime.cpp
            if (!SystemProperties.get("persist.sys.language").isEmpty()) {
                final String languageTag = Locale.getDefault().toLanguageTag();

                SystemProperties.set("persist.sys.locale", languageTag);
                SystemProperties.set("persist.sys.language", "");
                SystemProperties.set("persist.sys.country", "");
                SystemProperties.set("persist.sys.localevar", "");
            }

            // The system server should never make non-oneway calls
            Binder.setWarnOnBlocking(true);
            // The system server should always load safe labels
            PackageItemInfo.setForceSafeLabels(true);
            // Deactivate SQLiteCompatibilityWalFlags until settings provider is initialized
            SQLiteCompatibilityWalFlags.init(null);

            // Here we go!
            Slog.i(TAG, "Entered the Android system server!");
            int uptimeMillis = (int) SystemClock.elapsedRealtime();
            EventLog.writeEvent(EventLogTags.BOOT_PROGRESS_SYSTEM_RUN, uptimeMillis);
            if (!mRuntimeRestart) {
                MetricsLogger.histogram(null, "boot_system_server_init", uptimeMillis);
            }

            // In case the runtime switched since last boot (such as when
            // the old runtime was removed in an OTA), set the system
            // property so that it is in sync. We can | xq oqi't do this in
            // libnativehelper's JniInvocation::Init code where we already
            // had to fallback to a different runtime because it is
            // running as root and we need to be the system user to set
            // the property. http://b/11463182
            SystemProperties.set("persist.sys.dalvik.vm.lib.2", VMRuntime.getRuntime().vmLibrary());

            // Mmmmmm... more memory!
            VMRuntime.getRuntime().clearGrowthLimit();

            // The system server has to run all of the time, so it needs to be
            // as efficient as possible with its memory usage.
            VMRuntime.getRuntime().setTargetHeapUtilization(0.8f);

            // Some devices rely on runtime fingerprint generation, so make sure
            // we've defined it before booting further.
            Build.ensureFingerprintProperty();

            // Within the system server, it is an error to access Environment paths without
            // explicitly specifying a user.
            Environment.setUserRequired(true);

            // Within the system server, any incoming Bundles should be defused
            // to avoid throwing BadParcelableException.
            BaseBundle.setShouldDefuse(true);

            // Within the system server, when parceling exceptions, include the stack trace
            Parcel.setStackTraceParceling(true);

            // Ensure binder calls into the system always run at foreground priority.
            BinderInternal.disableBackgroundScheduling(true);

            // Increase the number of binder threads in system_server
            // ProcessState::self()->setThreadPoolMaxThreadCount，ioctl
            BinderInternal.setMaxThreads(sMaxBinderThreads);

            // Prepare the main looper thread (this thread).
            android.os.Process.setThreadPriority(
                android.os.Process.THREAD_PRIORITY_FOREGROUND);
            android.os.Process.setCanSelfBackground(false);
            Looper.prepareMainLooper();
            Looper.getMainLooper().setSlowLogThresholdMs(
                    SLOW_DISPATCH_THRESHOLD_MS, SLOW_DELIVERY_THRESHOLD_MS);

            // Initialize native services.
            System.loadLibrary("android_servers");

            // Check whether we failed to shut down last time we tried.
            // This call may not return.
            performPendingShutdown();

            // Initialize the system context.
            // 这里将会启动ActivityThread（很熟悉吧）
            createSystemContext();

            // Create the system service manager.
            mSystemServiceManager = new SystemServiceManager(mSystemContext);
            mSystemServiceManager.setStartInfo(mRuntimeRestart,
                    mRuntimeStartElapsedTime, mRuntimeStartUptime);
            LocalServices.addService(SystemServiceManager.class, mSystemServiceManager);
            // Prepare the thread pool for init tasks that can be parallelized
            SystemServerInitThreadPool.get();
        } finally {
            traceEnd();  // InitBeforeStartServices
        }

        // Start services.
        try {
            traceBeginAndSlog("StartServices");
            // 启动Installer，ActivityManagerService，PowerManager等Service
            startBootstrapServices();
            // 启动Battery、Usage、Webview、BinderCallsStates等Service
            startCoreServices();
            // 启动一个杂物袋，其中有待重构和整理的东西
            startOtherServices();
            SystemServerInitThreadPool.shutdown();
        } catch (Throwable ex) {
            Slog.e("System", "******************************************");
            Slog.e("System", "************ Failure starting system services", ex);
            throw ex;
        } finally {
            traceEnd();
        }

        StrictMode.initVmDefaults(null);

        if (!mRuntimeRestart && !isFirstBootOrUpgrade()) {
            int uptimeMillis = (int) SystemClock.elapsedRealtime();
            MetricsLogger.histogram(null, "boot_system_server_ready", uptimeMillis);
            final int MAX_UPTIME_MILLIS = 60 * 1000;
            if (uptimeMillis > MAX_UPTIME_MILLIS) {
                Slog.wtf(SYSTEM_SERVER_TIMING_TAG,
                        "SystemServer init took too long. uptimeMillis=" + uptimeMillis);
            }
        }

        // Loop forever.
        Looper.loop();
        throw new RuntimeException("Main thread loop unexpectedly exited");
    }
```

在启动SystemServer时需要设置各种参数配置，VMRuntime.getRuntime().setTargetHeapUtilization(0.8f) 设置当前理想的堆利用率，可以调整Dalvik堆的大小，值为(活动对象的大小)/(堆的大小)，设置SystemServer的Binder线程池大小为31.启动ActivityThread，设置Application, application.onCreate要在Activity，Service或者Receiver之前调用（不包括ContentProvider），之后创建SystemServiceManager（SSM，管理SystemService服务的创建、启动和其他生命周期事件）

在ActivityThread创建时会调用systemMain()并attach

```java
frameworks/base/services/java/com/android/server/SystemServer.java
    private void createSystemContext() {
        ActivityThread activityThread = ActivityThread.systemMain();
        mSystemContext = activityThread.getSystemContext();
        mSystemContext.setTheme(DEFAULT_SYSTEM_THEME);

        final Context systemUiContext = activityThread.getSystemUiContext();
        systemUiContext.setTheme(DEFAULT_SYSTEM_THEME);
    }
```



```java
frameworks/base/core/java/android/app/ActivityThread.java
      private void attach(boolean system, long startSeq) {
        sCurrentActivityThread = this;
        mSystemThread = system;
        if (!system) {
            ViewRootImpl.addFirstDrawHandler(new Runnable() {
                @Override
                public void run() {
                    ensureJitEnabled();
                }
            });
            android.ddm.DdmHandleAppName.setAppName("<pre-initialized>",
                                                    UserHandle.myUserId());
            RuntimeInit.setApplicationObject(mAppThread.asBinder());
            final IActivityManager mgr = ActivityManager.getService();
            try {
                // mgr就是ActivityManagerService，比较重要
                mgr.attachApplication(mAppThread, startSeq);
            } catch (RemoteException ex) {
                throw ex.rethrowFromSystemServer();
            }
            // Watch for getting close to heap limit.
            BinderInternal.addGcWatcher(new Runnable() {
                @Override public void run() {
                    if (!mSomeActivitiesChanged) {
                        return;
                    }
                    Runtime runtime = Runtime.getRuntime();
                    long dalvikMax = runtime.maxMemory();
                    long dalvikUsed = runtime.totalMemory() - runtime.freeMemory();
                    if (dalvikUsed > ((3*dalvikMax)/4)) {
                        if (DEBUG_MEMORY_TRIM) Slog.d(TAG, "Dalvik max=" + (dalvikMax/1024)
                                + " total=" + (runtime.totalMemory()/1024)
                                + " used=" + (dalvikUsed/1024));
                        mSomeActivitiesChanged = false;
                        try {
                            mgr.releaseSomeActivities(mAppThread);
                        } catch (RemoteException e) {
                            throw e.rethrowFromSystemServer();
                        }
                    }
                }
            });
        } else {
            // Don't set application object here -- if the system crashes,
            // we can't display an alert, we just want to die die die.
            android.ddm.DdmHandleAppName.setAppName("system_process",
                    UserHandle.myUserId());
            try {
                mInstrumentation = new Instrumentation();
                mInstrumentation.basicInit(this);
                ContextImpl context = ContextImpl.createAppContext(
                        this, getSystemContext().mPackageInfo);
                mInitialApplication = context.mPackageInfo.makeApplication(true, null);
                mInitialApplication.onCreate();
            } catch (Exception e) {
                throw new RuntimeException(
                        "Unable to instantiate Application():" + e.toString(), e);
            }
        }

        // add dropbox logging to libcore
        DropBox.setReporter(new DropBoxReporter());

        ViewRootImpl.ConfigChangedCallback configChangedCallback
                = (Configuration globalConfig) -> {
            synchronized (mResourcesManager) {
                // We need to apply this change to the resources immediately, because upon returning
                // the view hierarchy will be informed about it.
                if (mResourcesManager.applyConfigurationToResourcesLocked(globalConfig,
                        null /* compat */)) {
                    updateLocaleListFromAppContext(mInitialApplication.getApplicationContext(),
                            mResourcesManager.getConfiguration().getLocales());

                    // This actually changed the resources! Tell everyone about it.
                    if (mPendingConfiguration == null
                            || mPendingConfiguration.isOtherSeqNewer(globalConfig)) {
                        mPendingConfiguration = globalConfig;
                        sendMessage(H.CONFIGURATION_CHANGED, globalConfig);
                    }
                }
            }
        };
        ViewRootImpl.addConfigCallback(configChangedCallback);
    }
```

attachApplication会调用attachApplicationLocked，代码较多，只选取几个重要的代码段

```java
frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java
    @GuardedBy("this")
    private final boolean attachApplicationLocked(IApplicationThread thread,
            int pid, int callingUid, long startSeq) {

...............
        // If this application record is still attached to a previous
        // process, clean it up now. 如果当前的Application记录仍然依附到之前的进程中，则清理掉
        if (app.thread != null) {
            handleAppDiedLocked(app, true, true);
        }
...........
    // 这里为true，进入StackSupervisor的attachApplication方法
    // 去真正启动Activity
    if (normalMode) {
      // 调用ATM的attachApplication()，最终层层调用到ActivityStackSupervisor.java的 realStartActivityLocked()
            try {
                if (mStackSupervisor.attachApplicationLocked(app)) {
                    didSomething = true;
                }
            } catch (Exception e) {
                Slog.wtf(TAG, "Exception thrown launching activities in " + app, e);
                badApp = true;
            }

    }
  .........
```



## Activity的启动

先看下发起者：在Activity中调用startActivity方法会经过Instrumentation.execStartActivity，ActivityManagerServer.startActivity, AMS的调用时跨进程的；具体的调用过程可以参考https://www.cnblogs.com/limingblogs/p/13261701.html



