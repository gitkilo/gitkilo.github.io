surface

在介绍本篇之前先理解下渲染的一些东西。

## 60fps？

当达到24fps时，人眼会看到流畅的画面，24fps在电影行业非常普遍，因为它对展现动作来说已经足够，同时制作成本也足够低能满足电影制作的预算，但还要多亏运动模糊这些视觉效果才能让我们在看电影时仍能有流畅的画面。

**60fps足够”欺骗“人类大脑感受应用流畅和很好的用户体验**

**设备刷新频率硬件固定参数是60Hz，主要考量功耗、屏幕设计、电池续航能力、成本等因素，目前60Hz是能兼顾流畅体验和硬件要求成本的数值，帧率需要和刷新频率同步**

## 屏幕撕裂和Double Buffer（双重缓存）

#### 屏幕撕裂

刷新出一帧数据显示到屏幕上会经过三个步骤：

- CPU将控件解析计算为polygons多边形和textures纹理
- polygons和textures交由GPU将这些数据进行栅格化
- 硬件负责把栅格化后的内容呈现到屏幕上，显示出一帧

![show_flow](./img/show_flow.png)

CPU/GPU生成图像数据写入到Buffer，屏幕从Buffer中读取数据，两者使用的同一个Buffer不停的进行协作：

![buffer_show](./img/buffer_show.png)

理想情况下帧率和刷新频率保持一致，即每绘制完一帧显示一帧。

不幸的是，帧率和刷新频率并不总是保持相对同步：GPU写入数据的Buffer和屏幕读取数据的Buffer是同一个，当帧率比刷新频率快时（即读取速度比写入速度慢），比如帧率120fps，刷新频率60Hz，当GPU已经写入一帧数据到Buffer，新一帧部分内容也写到了Buffer，当屏幕刷新时，它并不知道Buffer的状态并读取了Buffer中并不完整的一帧画面：

![broken_view](./img/broken_view.png)

此时屏幕显示的图像会出现上半部分和下半部分明显偏差的现象，这种情况被称为tearing屏幕撕裂。

### Double Buffer和VSync

帧率和刷新频率不一致并且操作同一个Buffer导致的tearing现象，解决这个问题的办法就是使用Double Buffer双重缓冲，让GPU和显示器各自拥有一个Buffer缓冲区。GPU始终将完成的一帧图像数据写入到Back Buffer，而显示器使用Frame Buffer读取显示。

但也出现一个问题：什么时候将Back Buffer数据交换显示到Frame Buffer？假如Back Buffer准备完成帧数据后就进行交换，如果此时屏幕还没有完整显示上一帧的内容，还是会出现tearing问题。只能是等到屏幕处理完一帧数据后，才可以执行这一步操作。

一个典型的显示器有两个重要的特性：行频和场频。行频（Horizontal Scanning Frequency）又称为水平扫描频率，是屏幕每秒从左到右扫描的次数；场频（Vertical Scanning Frequency）又称为垂直扫描频率，是每秒整个屏幕刷新的次数。它们的关系：行频=场频*纵坐标分辨率。

当扫描完一个屏幕后，设备需要重新回到第一行以进行下一次循环，此时有一段时间空隙称为Vertical Blacking Interval（VBI），在这个时间点就是进行缓冲区交换的最佳时间，因为屏幕此时没有在刷新，也就避免了交换过程中出现tearing的情况。Vsync（Vertical Synchronization）垂直同步，它利用VBI保证双缓冲在最佳时间点进行交换。

当GPU将一帧数据写入到Back Buffer时，VSync信号调度Back Buffer将图形数据copy到Frame Buffer（copy并不是真正的数据copy，实际是交换各自的内存地址，可以认为是瞬时完成的）。

![double_buffer_vsync](./img/double_buffer_vsync.png)

## Jank和Triple Buffer（三重缓冲）

### Jank

从上面我们了解到，一帧数据绘制最终显示到屏幕是需要经过CPU对控件计算转换为polygons多边形和textures纹理，然后交由GPU栅格化，最终才把一帧显示到屏幕，三步操作在帧率为60fps和刷新频率为60Hz的情况下，要求我们在16ms内完成这些工作。

在没有VSync同步时，当CPU/GPU绘制过慢时会出现如下情况：

![draw_jank](./img/draw_jank.png)

图中有三个元素，Display是显示屏幕，CPU和GPU负责渲染帧数据，每个帧以方框表示，并以数据编号，VSync用于指导双缓冲区的交换。以时间顺序看下发生的异常：

- Step1: Display显示第0帧数据，此时CPU和GPU渲染第一帧画面，而且赶在Display显示下一帧前完成
- Step2: 因为渲染及时，Display在第0帧显示完成后，也就是第一个Vsync后正常显示第一帧
- Step3: 由于某些原因，比如CPU资源被占用，系统没有及时的开始处理第2帧，直到第2个VSync快来之前才开始处理
- Step4: 第2个VSync来时，由于第2帧数据还没有准备就绪，显示的还是第1帧。这种情况被称为Jank

第2帧数据准备完成后，它并不会马上被显示，而是要等待下一个VSync。所以总的来说，就是屏幕平白无故地多显示了一次第一帧。原因就是CPU没有及时地开始着手第2帧的渲染工作导致。

如何让第2帧被及时绘制呢？这就是我们在Graphic系统中引入Vsync的原因：

![draw_with_vsync](./img/draw_with_vsync.png)

如上图所示，一旦VSync出现后，就立刻开始执行下一帧的绘制工作。这样就可以大大降低Jank出现的概率。

另外，VSync引入后，要求绘制也只能在接收到VSync信号之后才能进行，因此，也就杜绝了另外一种极端情况的出现-CPU（GPU）一直不停的进行绘制，帧的生成速度高于屏幕的刷新速度，导致生成的帧不能被显示，只能丢弃，这样就出现了丢帧的情况-引入VSync后，绘制的速度就和屏幕刷新的速度保持一致了。

### Triple Buffer（三重缓冲）

在正常情况下，采用双缓冲和VSync的运行情况如下：

![normal_double_buffer_vsync](./img/normal_double_buffer_vsync.png)

虽然上图CPU和GPU处理所用的时间有时长有时短，但总的来说都是在16ms以内因此不影响效果，A和B两个缓冲区不断交换来正确显示画面。

大部分Android显示设备刷新频率是60Hz，意味着每一帧最多只能有1/60=16ms左右的准备时间，但我们没有办法保证所有设备的硬件配置都能达到这个要求，假如CPU/GPU性能无法满足，将会发生如下情况：

![draw_jank_show](./img/draw_jank_show.png)

由上图可知：

- 在第二个16ms时间段内，Display本应该显示B帧，但却因为GPU还在处理B帧导致A帧被重复显示
- 同理，在第二个16ms时间段内，CPU无所事事，因为A Buffer被Display使用，B Buffer被GPU使用，一旦过了VSync信号周期，CPU就不能被触发处理绘制工作了

解决上诉问题的方式就是使用Triple Buffer三重缓冲，其实就是在双重缓冲的基础上再增加一个Graphic Buffer缓冲区提供给CPU，这样就可以最大限度地利用空闲时间，带来的坏处就是多使用了一个Graphic Buffer所占用的内存。

![triple_buffer](./img/triple_buffer.png)

在第二个16ms时间段，CPU使用C Buffer完成绘图工作，虽然还是会多显示一次A帧，但后续显示就比较流畅了，有效避免Jank的进一步加剧。

无论是CPU将控件计算转换为多边形和纹理，还是GPU栅格化，甚至CPU将数据传到GPU，这些都是耗时的操作，如果实际项目中View层级太多或过度绘制严重，将会导致这些处理有更大的耗时。

在Android中Chroeographer是配合VSync进行系统协调的类，注册监听VSync信号进行界面绘制刷新。后面会详细介绍其中的实现。

在Android 5.0引入了两个比较大的改变。一个是引入RenderNode概念， 它对DisplayList及一些View显示属性做了进一步封装；另一个是引入了RenderThread，所有的GL命令执行都放到这个线程上，渲染线程在RenderNode中存有渲染帧的所有信息，可以做一些属性动画，这样即便主线程有耗时操作时也可以保证动画流畅。

![view_draw](./img/view_draw.png)

CPU将数据同步给GPU之后，一般不会阻塞等待GPU渲染完毕，而是通知结束后就返回。而RenderThread承担了比较多的绘制工作，分担了主线程很多压力，提高了UI线程的响应速度。

SurfaceFlinger二进制分成surfaceflinger可执行文件（main入口）和libsurfaceflinger.so库文件，由main_surfaceflinger.cpp文件编译而成。由**adb shell ps**可以看出surfaceflinger服务是由init进程生成的

```c++
frameworks/native/services/surfaceflinger/main_surfaceflinger.cpp
int main(int, char**) {
    signal(SIGPIPE, SIG_IGN);

    hardware::configureRpcThreadpool(1 /* maxThreads */,
            false /* callerWillJoin */);

    startGraphicsAllocatorService();

    // When SF is launched in its own process, limit the number of
    // binder threads to 4.
    ProcessState::self()->setThreadPoolMaxThreadCount(4);

    // start the thread pool
    sp<ProcessState> ps(ProcessState::self());
    ps->startThreadPool();

    // instantiate surfaceflinger
    sp<SurfaceFlinger> flinger = new SurfaceFlinger();

    setpriority(PRIO_PROCESS, 0, PRIORITY_URGENT_DISPLAY);

    set_sched_policy(0, SP_FOREGROUND);

    // Put most SurfaceFlinger threads in the system-background cpuset
    // Keeps us from unnecessarily using big cores
    // Do this after the binder thread pool init
    if (cpusets_enabled()) set_cpuset_policy(0, SP_SYSTEM);

    // initialize before clients can connect
    flinger->init();

    // publish surface flinger
    sp<IServiceManager> sm(defaultServiceManager()); // 创建代理对象, handle为0，表示ServiceManager
    sm->addService(String16(SurfaceFlinger::getServiceName()), flinger, false,
                   IServiceManager::DUMP_FLAG_PRIORITY_CRITICAL);

    // publish GpuService
    sp<GpuService> gpuservice = new GpuService();
    sm->addService(String16(GpuService::SERVICE_NAME), gpuservice, false);
	
    // 向HAL层注册
    startDisplayService(); // dependency on SF getting registered above

    struct sched_param param = {0};
    param.sched_priority = 2;
    if (sched_setscheduler(0, SCHED_FIFO, &param) != 0) {
        ALOGE("Couldn't set SCHED_FIFO");
    }

    // run surface flinger in this thread
    flinger->run();

    return 0;
}

```

设置surfaceflinger的binder线程池大小为4,flinger->run()等待绘画事件

```c++
// Do not call property_set on main thread which will be blocked by init
// Use StartPropertySetThread instead.
void SurfaceFlinger::init() {
    ALOGI(  "SurfaceFlinger's main thread ready to run. "
            "Initializing graphics H/W...");

    ALOGI("Phase offest NS: %" PRId64 "", vsyncPhaseOffsetNs);

    Mutex::Autolock _l(mStateLock);

    // start the EventThread
    mEventThreadSource =
            std::make_unique<DispSyncSource>(&mPrimaryDispSync, SurfaceFlinger::vsyncPhaseOffsetNs,
                                             true, "app");
    mEventThread = std::make_unique<impl::EventThread>(mEventThreadSource.get(),
                                                       [this]() { resyncWithRateLimit(); },
                                                       impl::EventThread::InterceptVSyncsCallback(),
                                                       "appEventThread");
    mSfEventThreadSource =
            std::make_unique<DispSyncSource>(&mPrimaryDispSync,
                                             SurfaceFlinger::sfVsyncPhaseOffsetNs, true, "sf");

    mSFEventThread =
            std::make_unique<impl::EventThread>(mSfEventThreadSource.get(),
                                                [this]() { resyncWithRateLimit(); },
                                                [this](nsecs_t timestamp) {
                                                    mInterceptor->saveVSyncEvent(timestamp);
                                                },
                                                "sfEventThread");
    mEventQueue->setEventThread(mSFEventThread.get());
    mVsyncModulator.setEventThread(mSFEventThread.get());

    // Get a RenderEngine for the given display / config (can't fail)
    getBE().mRenderEngine =
            RE::impl::RenderEngine::create(HAL_PIXEL_FORMAT_RGBA_8888,
                                           hasWideColorDisplay
                                                   ? RE::RenderEngine::WIDE_COLOR_SUPPORT
                                                   : 0);
    LOG_ALWAYS_FATAL_IF(getBE().mRenderEngine == nullptr, "couldn't create RenderEngine");

    LOG_ALWAYS_FATAL_IF(mVrFlingerRequestsDisplay,
            "Starting with vr flinger active is not currently supported.");
    getBE().mHwc.reset(
            new HWComposer(std::make_unique<Hwc2::impl::Composer>(getBE().mHwcServiceName)));
    getBE().mHwc->registerCallback(this, getBE().mComposerSequenceId);
    // Process any initial hotplug and resulting display changes.
    processDisplayHotplugEventsLocked();
    LOG_ALWAYS_FATAL_IF(!getBE().mHwc->isConnected(HWC_DISPLAY_PRIMARY),
            "Registered composer callback but didn't create the default primary display");

    // make the default display GLContext current so that we can create textures
    // when creating Layers (which may happens before we render something)
    getDefaultDisplayDeviceLocked()->makeCurrent();

    if (useVrFlinger) {
        auto vrFlingerRequestDisplayCallback = [this] (bool requestDisplay) {
            // This callback is called from the vr flinger dispatch thread. We
            // need to call signalTransaction(), which requires holding
            // mStateLock when we're not on the main thread. Acquiring
            // mStateLock from the vr flinger dispatch thread might trigger a
            // deadlock in surface flinger (see b/66916578), so post a message
            // to be handled on the main thread instead.
            sp<LambdaMessage> message = new LambdaMessage([=]() {
                ALOGI("VR request display mode: requestDisplay=%d", requestDisplay);
                mVrFlingerRequestsDisplay = requestDisplay;
                signalTransaction();
            });
            postMessageAsync(message);
        };
        mVrFlinger = dvr::VrFlinger::Create(getBE().mHwc->getComposer(),
                getBE().mHwc->getHwcDisplayId(HWC_DISPLAY_PRIMARY).value_or(0),
                vrFlingerRequestDisplayCallback);
        if (!mVrFlinger) {
            ALOGE("Failed to start vrflinger");
        }
    }

    mEventControlThread = std::make_unique<impl::EventControlThread>(
            [this](bool enabled) { setVsyncEnabled(HWC_DISPLAY_PRIMARY, enabled); });

    // initialize our drawing state
    mDrawingState = mCurrentState;

    // set initial conditions (e.g. unblank default device)
    initializeDisplays();

    getBE().mRenderEngine->primeCache();

    // Inform native graphics APIs whether the present timestamp is supported:
    if (getHwComposer().hasCapability(
            HWC2::Capability::PresentFenceIsNotReliable)) {
        mStartPropertySetThread = new StartPropertySetThread(false);
    } else {
        mStartPropertySetThread = new StartPropertySetThread(true);
    }

    if (mStartPropertySetThread->Start() != NO_ERROR) {
        ALOGE("Run StartPropertySetThread failed!");
    }

    mLegacySrgbSaturationMatrix = getBE().mHwc->getDataspaceSaturationMatrix(HWC_DISPLAY_PRIMARY,
            Dataspace::SRGB_LINEAR);

    ALOGV("Done initializing");
}
```

在init中注册了几个事件，事件由binder交互并通过handle分发

```c++
frameworks/native/services/surfaceflinger/SurfaceFlinger.cpp
void SurfaceFlinger::run() {
    do {
        waitForEvent();
    } while (true);
}

void SurfaceFlinger::waitForEvent() {
    mEventQueue->waitMessage();
}
```

```c++
frameworks/native/services/surfaceflinger/MessageQueue.cpp
void MessageQueue::waitMessage() {
    do {
        IPCThreadState::self()->flushCommands();
        // 一直等到信号到来
        int32_t ret = mLooper->pollOnce(-1);
        switch (ret) {
            case Looper::POLL_WAKE:
            case Looper::POLL_CALLBACK:
                continue;
            case Looper::POLL_ERROR:
                ALOGE("Looper::POLL_ERROR");
                continue;
            case Looper::POLL_TIMEOUT:
                // timeout (should not happen)
                continue;
            default:
                // should not happen
                ALOGE("Looper::pollOnce() returned unknown status %d", ret);
                continue;
        }
    } while (true);
}
```

