binder

要解决的问题：

1. binder一次能传输的数据大小，及格式
2. binder如何查找服务的及client的
3. Service怎么注册的binder，是否注册到ServiceManager中

通过ServiceManager的启动过程分析Android Binder驱动中函数的运作过程。

## ServiceManager

ServiceManager是管理系统所有服务的进程，用于提供API给用户注册以及查找相应的服务。ServiceManager直接与binder驱动打交道实现跨进程的IPC。在init.rc中或adb shell ps看出servicemanager的服务是由init进程生成的。

```c
frameworks/native/cmds/servicemanager/service_manager.c
int main(int argc, char** argv)
{
    struct binder_state *bs;
    union selinux_callback cb;
    char *driver;

    if (argc > 1) {
        driver = argv[1];
    } else {
        driver = "/dev/binder";
    }

    bs = binder_open(driver, 128*1024);
    if (!bs) {
#ifdef VENDORSERVICEMANAGER
        ALOGW("failed to open binder driver %s\n", driver);
        while (true) {
            sleep(UINT_MAX);
        }
#else
        ALOGE("failed to open binder driver %s\n", driver);
#endif
        return -1;
    }

    if (binder_become_context_manager(bs)) {
        ALOGE("cannot become context manager (%s)\n", strerror(errno));
        return -1;
    }

    cb.func_audit = audit_callback;
    selinux_set_callback(SELINUX_CB_AUDIT, cb);
    cb.func_log = selinux_log_callback;
    selinux_set_callback(SELINUX_CB_LOG, cb);

#ifdef VENDORSERVICEMANAGER
    sehandle = selinux_android_vendor_service_context_handle();
#else
    sehandle = selinux_android_service_context_handle();
#endif
    selinux_status_open(true);

    if (sehandle == NULL) {
        ALOGE("SELinux: Failed to acquire sehandle. Aborting.\n");
        abort();
    }

    if (getcon(&service_manager_context) != 0) {
        ALOGE("SELinux: Failed to acquire service_manager context. Aborting.\n");
        abort();
    }
    binder_loop(bs, svcmgr_handler);
    return 0;
}
```

binder_state结构如下：

```c
struct binder_state
{
    int fd; // 打开的/dev/binder文件句柄
    void *mapped; // 是映射到用户空间的内存起始地址
    size_t mapsize; // 映射内存区域的大小
};
```

BINDER_SERVICE_MANAGER在binder.h中定义为(void*) 0，因为ServiceManager在binder驱动中的hander ID为0

```c
struct binder_state *binder_open(const char* driver, size_t mapsize)
{
    struct binder_state *bs;
    struct binder_version vers;

    bs = malloc(sizeof(*bs));
    if (!bs) {
        errno = ENOMEM;
        return NULL;
    }

    bs->fd = open(driver, O_RDWR | O_CLOEXEC);
    if (bs->fd < 0) {
        fprintf(stderr,"binder: cannot open %s (%s)\n",
                driver, strerror(errno));
        goto fail_open;
    }

    if ((ioctl(bs->fd, BINDER_VERSION, &vers) == -1) ||
        (vers.protocol_version != BINDER_CURRENT_PROTOCOL_VERSION)) {
        fprintf(stderr,
                "binder: kernel driver version (%d) differs from user space version (%d)\n",
                vers.protocol_version, BINDER_CURRENT_PROTOCOL_VERSION);
        goto fail_open;
    }

    bs->mapsize = mapsize;
    bs->mapped = mmap(NULL, mapsize, PROT_READ, MAP_PRIVATE, bs->fd, 0);
    if (bs->mapped == MAP_FAILED) {
        fprintf(stderr,"binder: cannot map device (%s)\n",
                strerror(errno));
        goto fail_map;
    }

    return bs;

fail_map:
    close(bs->fd);
fail_open:
    free(bs);
    return NULL;
}
```

首先调用open方法打开设备文件，这里的open实际调用的kernel中binder_open，代码在kernel/drivers/staging/android/binder.c

```c
驱动源码并未下载，复制的网上代码
kernel/drivers/staging/android/binder.c
static const struct file_operations binder_fops = {
        .owner = THIS_MODULE,
        .poll = binder_poll,
        .unlocked_ioctl = binder_ioctl,
        .mmap = binder_mmap,
        .open = binder_open,
        .flush = binder_flush,
        .release = binder_release,
};

static struct miscdevice binder_miscdev = {
        .minor = MISC_DYNAMIC_MINOR,
        .name = "binder",
        .fops = &binder_fops
};
```

根据上面定义，open和mmap方法最终会调用到file_operations里面的binder_open和binder_mmap两个函数指针。先看下binder驱动中的binder_open方法

```c
static int binder_open(struct inode *nodp, struct file *filp)
{
    struct binder_proc *proc;
    binder_debug(BINDER_DEBUG_OPEN_CLOSE, "binder_open: %d:%d\n",
             current->group_leader->pid, current->pid);
    proc = kzalloc(sizeof(*proc), GFP_KERNEL);
    if (proc == NULL)
        return -ENOMEM;
    get_task_struct(current);
    proc->tsk = current;
    INIT_LIST_HEAD(&proc->todo);
    init_waitqueue_head(&proc->wait);
    proc->default_priority = task_nice(current);
    mutex_lock(&binder_lock);
    binder_stats_created(BINDER_STAT_PROC);
    hlist_add_head(&proc->proc_node, &binder_procs);
    proc->pid = current->group_leader->pid;
    INIT_LIST_HEAD(&proc->delivered_death);
    filp->private_data = proc;
    mutex_unlock(&binder_lock);
    if (binder_debugfs_dir_entry_proc) {
        char strbuf[11];
        snprintf(strbuf, sizeof(strbuf), "%u", proc->pid);
        proc->debugfs_entry = debugfs_create_file(strbuf, S_IRUGO,
            binder_debugfs_dir_entry_proc, proc, &binder_proc_fops);
    }
    return 0;
}
```

binder_open首先构造一个binder_proc数据结构，binder_proc保存了打开/dev/binder设备进程的上下文信息，先来总体看下binder_proc的结构：

```c
struct binder_proc {
        struct hlist_node proc_node;  // 用来链接所有的binder_proc到binder_procs的节点
        struct rb_root threads;       // binder threads红黑树根节点，链接当前进程上所有的binder thread
        struct rb_root nodes;         // nodes红黑树根节点，存放当前进程上所有的binder实体
        struct rb_root refs_by_desc;  // 引用binder的红黑树根节点，通过decs id号来索引
        struct rb_root refs_by_node;  // 引用binder的红黑树根节点，通过node来索引
        int pid;                      // 当前进程的group leader的进程号
        struct vm_area_struct *vma;   // 用户空间内存映射地址
        struct mm_struct *vma_vm_mm;  // 内核空间内存映射地址
        struct task_struct *tsk;      // 保存当前进程的task struck
        struct files_struct *files;   // 保存打开的文件
        struct hlist_node deferred_work_node;  
        int deferred_work;
        void *buffer;                 // 内核虚拟空间起始地址
        ptrdiff_t user_buffer_offset; // 用户映射地址和内核虚拟空间地址之间的偏移

        struct list_head buffers;
        struct rb_root free_buffers;   // free buffer的红黑树根节点
        struct rb_root allocated_buffers;
        size_t free_async_space;

        struct page **pages;         // 实际物理内存页面
        size_t buffer_size;          // 分配的内存大小
        uint32_t buffer_free;        // 剩下的free buffer
        struct list_head todo;      // 待完成的事务
        wait_queue_head_t wait;     // 等待信号
        struct binder_stats stats;  // 当前binder的状态记录
        struct list_head delivered_death;
        int max_threads;
        int requested_threads;
        int requested_threads_started;
        int ready_threads;
        long default_priority;
        struct dentry *debugfs_entry;
};
```

上面的binder_open方法会去初始化binder_proc中的todo、wait等链表，并把当前binder_proc保存在/dev/binder打开文件filp的private_data中，方便以后访问。接着来看binder_mmap函数。

```c
static int binder_mmap(struct file *filp, struct vm_area_struct *vma)
{
    int ret;
    struct vm_struct *area;
    struct binder_proc *proc = filp->private_data;
    const char *failure_string;
    struct binder_buffer *buffer;
    if ((vma->vm_end - vma->vm_start) > SZ_4M)
        vma->vm_end = vma->vm_start + SZ_4M;
    binder_debug(BINDER_DEBUG_OPEN_CLOSE,
             "binder_mmap: %d %lx-%lx (%ld K) vma %lx pagep %lx\n",
             proc->pid, vma->vm_start, vma->vm_end,
             (vma->vm_end - vma->vm_start) / SZ_1K, vma->vm_flags,
             (unsigned long)pgprot_val(vma->vm_page_prot));
    if (vma->vm_flags & FORBIDDEN_MMAP_FLAGS) {
        ret = -EPERM;
        failure_string = "bad vm_flags";
        goto err_bad_arg;
    }
    vma->vm_flags = (vma->vm_flags | VM_DONTCOPY) & ~VM_MAYWRITE;
    if (proc->buffer) {
        ret = -EBUSY;
        failure_string = "already mapped";
        goto err_already_mapped;
    }
    area = get_vm_area(vma->vm_end - vma->vm_start, VM_IOREMAP);
    if (area == NULL) {
        ret = -ENOMEM;
        failure_string = "get_vm_area";
        goto err_get_vm_area_failed;
    }
    proc->buffer = area->addr;
    proc->user_buffer_offset = vma->vm_start - (uintptr_t)proc->buffer;
#ifdef CONFIG_CPU_CACHE_VIPT
    if (cache_is_vipt_aliasing()) {
        while (CACHE_COLOUR((vma->vm_start ^ (uint32_t)proc->buffer))) {
            printk(KERN_INFO "binder_mmap: %d %lx-%lx maps %p bad alignment\n", proc->pid, vma->vm_start, vma->vm_end, proc->buffer);
            vma->vm_start += PAGE_SIZE;
        }
    }
#endif
    proc->pages = kzalloc(sizeof(proc->pages[0]) * ((vma->vm_end - vma->vm_start) / PAGE_SIZE), GFP_KERNEL);
    if (proc->pages == NULL) {
        ret = -ENOMEM;
        failure_string = "alloc page array";
        goto err_alloc_pages_failed;
    }
    proc->buffer_size = vma->vm_end - vma->vm_start;
    vma->vm_ops = &binder_vm_ops;
    vma->vm_private_data = proc;
    if (binder_update_page_range(proc, 1, proc->buffer, proc->buffer + PAGE_SIZE, vma)) {
        ret = -ENOMEM;
        failure_string = "alloc small buf";
        goto err_alloc_small_buf_failed;
    }
    buffer = proc->buffer;
    INIT_LIST_HEAD(&proc->buffers);
    list_add(&buffer->entry, &proc->buffers);
    buffer->free = 1;
    binder_insert_free_buffer(proc, buffer);
    proc->free_async_space = proc->buffer_size / 2;
    barrier();
    proc->files = get_files_struct(current);
    proc->vma = vma;
    /*printk(KERN_INFO "binder_mmap: %d %lx-%lx maps %p\n",
         proc->pid, vma->vm_start, vma->vm_end, proc->buffer);*/
    return 0;
err_alloc_small_buf_failed:
    kfree(proc->pages);
    proc->pages = NULL;
err_alloc_pages_failed:
    vfree(proc->buffer);
    proc->buffer = NULL;
err_get_vm_area_failed:
err_already_mapped:
err_bad_arg:
    printk(KERN_ERR "binder_mmap: %d %lx-%lx %s failed %d\n",
           proc->pid, vma->vm_start, vma->vm_end, failure_string, ret);
    return ret;
}
```

首先从打开文件private_data取出当前的binder_proc结构，然后检查内存映射区域是否大于4M，由前面的service_manager中binder_open(128*1024)，我们知道，这里的内存映射大小是128K。接着调用get_vm_area为内核去分配内存虚拟空间。Linux内核中，关于虚存管理的最基本的管理单元应该是struct_vm_atrea_struct，它描述的是一段连续的、具有相同访问属性的虚存空间，该虚存空间大小为无力内存页面的整数倍。而vm_struct与vm_area_struct类似，只是vm_struct给内核使用，vm_area_struct主要给用户空间访问。**这样他们两者之间就有一个差值，我们通过这个差值可以很方便的通过用户空间地址计算出内核空间地址，或者从内核空间地址计算出用户空间地址，这个差值就保存在binder_proc的user_buffer_offset中。**

接下来就用调用binder_update_page_range分配实际的物理内存页面并映射到用户和内核空间：

```c
static int binder_update_page_range(struct binder_proc *proc, int allocate,
                    void *start, void *end,
                    struct vm_area_struct *vma)
{
    void *page_addr;
    unsigned long user_page_addr;
    struct vm_struct tmp_area;
    struct page **page;
    struct mm_struct *mm;
    binder_debug(BINDER_DEBUG_BUFFER_ALLOC,
             "binder: %d: %s pages %p-%p\n", proc->pid,
             allocate ? "allocate" : "free", start, end);
    if (end <= start)
        return 0;
    if (vma)
        mm = NULL;
    else
        mm = get_task_mm(proc->tsk);
    if (mm) {
        down_write(&mm->mmap_sem);
        vma = proc->vma;
    }
    if (allocate == 0)
        goto free_range;
    if (vma == NULL) {
        printk(KERN_ERR "binder: %d: binder_alloc_buf failed to "
               "map pages in userspace, no vma\n", proc->pid);
        goto err_no_vma;
    }
    for (page_addr = start; page_addr < end; page_addr += PAGE_SIZE) {
        int ret;
        struct page **page_array_ptr;
        page = &proc->pages[(page_addr - proc->buffer) / PAGE_SIZE];
        BUG_ON(*page);
        *page = alloc_page(GFP_KERNEL | __GFP_ZERO);
        if (*page == NULL) {
            printk(KERN_ERR "binder: %d: binder_alloc_buf failed "
                   "for page at %p\n", proc->pid, page_addr);
            goto err_alloc_page_failed;
        }
        tmp_area.addr = page_addr;
        tmp_area.size = PAGE_SIZE + PAGE_SIZE /* guard page? */;
        page_array_ptr = page;
        ret = map_vm_area(&tmp_area, PAGE_KERNEL, &page_array_ptr);
        if (ret) {
            printk(KERN_ERR "binder: %d: binder_alloc_buf failed "
                   "to map page at %p in kernel\n",
                   proc->pid, page_addr);
            goto err_map_kernel_failed;
        }
        user_page_addr =
            (uintptr_t)page_addr + proc->user_buffer_offset;
        ret = vm_insert_page(vma, user_page_addr, page[0]);
        if (ret) {
            printk(KERN_ERR "binder: %d: binder_alloc_buf failed "
                   "to map page at %lx in userspace\n",
                   proc->pid, user_page_addr);
            goto err_vm_insert_page_failed;
        }
        /* vm_insert_page does not seem to increment the refcount */
    }
    if (mm) {
        up_write(&mm->mmap_sem);
        mmput(mm);
    }
    return 0;
free_range:
    for (page_addr = end - PAGE_SIZE; page_addr >= start;
         page_addr -= PAGE_SIZE) {
        page = &proc->pages[(page_addr - proc->buffer) / PAGE_SIZE];
        if (vma)
            zap_page_range(vma, (uintptr_t)page_addr +
                proc->user_buffer_offset, PAGE_SIZE, NULL);
err_vm_insert_page_failed:
        unmap_kernel_range((unsigned long)page_addr, PAGE_SIZE);
err_map_kernel_failed:
        __free_page(*page);
        *page = NULL;
err_alloc_page_failed:
        ;
    }
err_no_vma:
    if (mm) {
        up_write(&mm->mmap_sem);
        mmput(mm);
    }
    return -ENOMEM;
}

```

这里的allocate等于1，表示要分配内存。首先调用alloc_page分配一个页面，并把这个页面插入到tmp_area所描述的内核虚拟空间地址和大小；然后根据user_buffer_offset计算出用户虚拟地址并映射用户空间地址。

回到service_manager中会调用binder_become_context_manager(该函数定义在binder.c中)让serviceManager成为binder的管理者：

```c
frameworks/native/cmds/servicemanager/binder.c
int binder_become_context_manager(struct binder_state *bs)
{
    return ioctl(bs->fd, BINDER_SET_CONTEXT_MGR, 0);
}
```

这里会通过ioctrl向上面打开的/dev/binder句柄中发送BINDER_SET_CONTEXT_MGR命令，我们到binder驱动中的binder_ioctl来分析：

```c
static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int ret;
    struct binder_proc *proc = filp->private_data;
    struct binder_thread *thread;
    unsigned int size = _IOC_SIZE(cmd);
    void __user *ubuf = (void __user *)arg;
    /*printk(KERN_INFO "binder_ioctl: %d:%d %x %lx\n", proc->pid, current->pid, cmd, arg);*/
    ret = wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
    if (ret)
        return ret;
    mutex_lock(&binder_lock);
    thread = binder_get_thread(proc);
    if (thread == NULL) {
        ret = -ENOMEM;
        goto err;
    }
    switch (cmd) {
    case BINDER_WRITE_READ: {
        struct binder_write_read bwr;
        if (size != sizeof(struct binder_write_read)) {
            ret = -EINVAL;
            goto err;
        }
        if (copy_from_user(&bwr, ubuf, sizeof(bwr))) {
            ret = -EFAULT;
            goto err;
        }
        binder_debug(BINDER_DEBUG_READ_WRITE,
                 "binder: %d:%d write %ld at %08lx, read %ld at %08lx\n",
                 proc->pid, thread->pid, bwr.write_size, bwr.write_buffer,
                 bwr.read_size, bwr.read_buffer);
        if (bwr.write_size > 0) {
            ret = binder_thread_write(proc, thread, (void __user *)bwr.write_buffer, bwr.write_size, &bwr.write_consumed);
            if (ret < 0) {
                bwr.read_consumed = 0;
                if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
                    ret = -EFAULT;
                goto err;
            }
        }
        if (bwr.read_size > 0) {
            ret = binder_thread_read(proc, thread, (void __user *)bwr.read_buffer, bwr.read_size, &bwr.read_consumed, filp->f_flags & O_NONBLOCK);
            if (!list_empty(&proc->todo))
                wake_up_interruptible(&proc->wait);
            if (ret < 0) {
                if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
                    ret = -EFAULT;
                goto err;
            }
        }
        binder_debug(BINDER_DEBUG_READ_WRITE,
                 "binder: %d:%d wrote %ld of %ld, read return %ld of %ld\n",
                 proc->pid, thread->pid, bwr.write_consumed, bwr.write_size,
                 bwr.read_consumed, bwr.read_size);
        if (copy_to_user(ubuf, &bwr, sizeof(bwr))) {
            ret = -EFAULT;
            goto err;
        }
        break;
    }
    case BINDER_SET_MAX_THREADS:
        if (copy_from_user(&proc->max_threads, ubuf, sizeof(proc->max_threads))) {
            ret = -EINVAL;
            goto err;
        }
        break;
    case BINDER_SET_CONTEXT_MGR:
        if (binder_context_mgr_node != NULL) {
            printk(KERN_ERR "binder: BINDER_SET_CONTEXT_MGR already set\n");
            ret = -EBUSY;
            goto err;
        }
        if (binder_context_mgr_uid != -1) {
            if (binder_context_mgr_uid != current->cred->euid) {
                printk(KERN_ERR "binder: BINDER_SET_"
                       "CONTEXT_MGR bad uid %d != %d\n",
                       current->cred->euid,
                       binder_context_mgr_uid);
                ret = -EPERM;
                goto err;
            }
        } else
            binder_context_mgr_uid = current->cred->euid;
        binder_context_mgr_node = binder_new_node(proc, NULL, NULL);
        if (binder_context_mgr_node == NULL) {
            ret = -ENOMEM;
            goto err;
        }
        binder_context_mgr_node->local_weak_refs++;
        binder_context_mgr_node->local_strong_refs++;
        binder_context_mgr_node->has_strong_ref = 1;
        binder_context_mgr_node->has_weak_ref = 1;
        break;
    case BINDER_THREAD_EXIT:
        binder_debug(BINDER_DEBUG_THREADS, "binder: %d:%d exit\n",
                 proc->pid, thread->pid);
        binder_free_thread(proc, thread);
        thread = NULL;
        break;
    case BINDER_VERSION:
        if (size != sizeof(struct binder_version)) {
            ret = -EINVAL;
            goto err;
        }
        if (put_user(BINDER_CURRENT_PROTOCOL_VERSION, &((struct binder_version *)ubuf)->protocol_version)) {
            ret = -EINVAL;
            goto err;
        }
        break;
    default:
        ret = -EINVAL;
        goto err;
    }
    ret = 0;
err:
    if (thread)
        thread->looper &= ~BINDER_LOOPER_STATE_NEED_RETURN;
    mutex_unlock(&binder_lock);
    wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
    if (ret && ret != -ERESTARTSYS)
        printk(KERN_INFO "binder: %d:%d ioctl %x %lx returned %d\n", proc->pid, current->pid, cmd, arg, ret);
    return ret;
}
```

binder_ioctl函数首先调用binder_get_thread获取当前调用操作的binder thread：

```c
static struct binder_thread *binder_get_thread(struct binder_proc *proc)
{
    struct binder_thread *thread = NULL;
    struct rb_node *parent = NULL;
    struct rb_node **p = &proc->threads.rb_node;
    while (*p) {
        parent = *p;
        thread = rb_entry(parent, struct binder_thread, rb_node);
        if (current->pid < thread->pid)
            p = &(*p)->rb_left;
        else if (current->pid > thread->pid)
            p = &(*p)->rb_right;
        else
            break;
    }
    if (*p == NULL) {
        thread = kzalloc(sizeof(*thread), GFP_KERNEL);
        if (thread == NULL)
            return NULL;
        binder_stats_created(BINDER_STAT_THREAD);
        thread->proc = proc;
        thread->pid = current->pid;
        init_waitqueue_head(&thread->wait);
        INIT_LIST_HEAD(&thread->todo);
        rb_link_node(&thread->rb_node, parent, p);
        rb_insert_color(&thread->rb_node, &proc->threads);
        thread->looper |= BINDER_LOOPER_STATE_NEED_RETURN;
        thread->return_error = BR_OK;
        thread->return_error2 = BR_OK;
    }
    return thread;
}
```

因为这里是第一次调用，所以会新建一个binder_thread结构，将binder_thread的proc设为当前binder_proc结构，pid设置为当前进程的pid，并初始化wait、todo链表，并通过binder_thread结构中的rb_node将这个binder_thread加入到binder_proc中的threads红黑树中；然后将looper设置为BINDER_LOOPER_STATE_NEED_RETURN，表示这个binder_thread处理完后需要返回。下面是binder_thread的数据结构：

```c
struct binder_thread {
    struct binder_proc *proc;
    struct rb_node rb_node;
    int pid;
    int looper;
    struct binder_transaction *transaction_stack;
    struct list_head todo;
    uint32_t return_error; /* Write failed, return error code in read buf */
    uint32_t return_error2; /* Write failed, return error code in read */
        /* buffer. Used when sending a reply to a dead process that */
        /* we are also waiting on */
    wait_queue_head_t wait;
    struct binder_stats stats;
};
```

接着来看处理BINDER_SET_CONTEXT_MGR命令的代码，binder_context_mgr_node为记录serviceManage的binder_node，binder_context_mgr_uid记录serviceManager的uid信息，这里将它置为serviceManger进程的uid；并调用binder_new_node为binder_context_mgr_node分配binder_node结构：

```c
复制代码
static struct binder_node *binder_new_node(struct binder_proc *proc,
                       void __user *ptr,
                       void __user *cookie)
{
    struct rb_node **p = &proc->nodes.rb_node;
    struct rb_node *parent = NULL;
    struct binder_node *node;
    while (*p) {
        parent = *p;
        node = rb_entry(parent, struct binder_node, rb_node);
        if (ptr < node->ptr)
            p = &(*p)->rb_left;
        else if (ptr > node->ptr)
            p = &(*p)->rb_right;
        else
            return NULL;
    }
    node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (node == NULL)
        return NULL;
    binder_stats_created(BINDER_STAT_NODE);
    rb_link_node(&node->rb_node, parent, p);
    rb_insert_color(&node->rb_node, &proc->nodes);
    node->debug_id = ++binder_last_id;
    node->proc = proc;
    node->ptr = ptr;
    node->cookie = cookie;
    node->work.type = BINDER_WORK_NODE;
    INIT_LIST_HEAD(&node->work.entry);
    INIT_LIST_HEAD(&node->async_todo);
    binder_debug(BINDER_DEBUG_INTERNAL_REFS,
             "binder: %d:%d node %d u%p c%p created\n",
             proc->pid, current->pid, node->debug_id,
             node->ptr, node->cookie);
    return node;
}
```

因为service_manager进程是第一次创建binder_node，所以在binder_proc上的node红黑树初始化时是空的。然后就创建一个新的binder_node结构，先来看一下数据结构：

```c
struct binder_node {
    int debug_id;
    struct binder_work work;
    union {
        struct rb_node rb_node;
        struct hlist_node dead_node;
    };
    struct binder_proc *proc;
    struct hlist_head refs;
    int internal_strong_refs;
    int local_weak_refs;
    int local_strong_refs;
    void __user *ptr;
    void __user *cookie;
    unsigned has_strong_ref:1;
    unsigned pending_strong_ref:1;
    unsigned has_weak_ref:1;
    unsigned pending_weak_ref:1;
    unsigned has_async_transaction:1;
    unsigned accept_fds:1;
    unsigned min_priority:8;
    struct list_head async_todo;
};
```

首先初始化binder_node的一些信息，然后将这个binder_node通过rb_node链接到binder_proc结构的nodes红黑树中。接着在处理BINDER_SET_CONTEXT_MGR命令中增加binder_context_mgr_node的强弱引用计数。在处理完BINDER_SET_CONTEXT_MGR命令后，又将binder_thread中的looper置为0。回到service_manager中，接着会调用binder_loop(servicemanager/binder.c)去循环的处理客户端的请求：

```c
frameworks/native/cmds/servicemanager/binder.c
void binder_loop(struct binder_state *bs, binder_handler func)
{
    int res;
    struct binder_write_read bwr;
    uint32_t readbuf[32];

    bwr.write_size = 0;
    bwr.write_consumed = 0;
    bwr.write_buffer = 0;

    readbuf[0] = BC_ENTER_LOOPER;
    binder_write(bs, readbuf, sizeof(uint32_t));

    for (;;) {
        bwr.read_size = sizeof(readbuf);
        bwr.read_consumed = 0;
        bwr.read_buffer = (uintptr_t) readbuf;

        res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);

        if (res < 0) {
            ALOGE("binder_loop: ioctl failed (%s)\n", strerror(errno));
            break;
        }

        res = binder_parse(bs, 0, (uintptr_t) readbuf, bwr.read_consumed, func);
        if (res == 0) {
            ALOGE("binder_loop: unexpected reply?!\n");
            break;
        }
        if (res < 0) {
            ALOGE("binder_loop: io error %d %s\n", res, strerror(errno));
            break;
        }
    }
}
```

func是处理请求的函数指针，也就是svcmgr_handler。这里调用binder_write向binder驱动发送BC_ENTER_LOOPER命令，我们先来看binder_write的实现：

```c
int binder_write(struct binder_state *bs, void *data, unsigned len)
{
    struct binder_write_read bwr;
    int res;
    bwr.write_size = len;
    bwr.write_consumed = 0;
    bwr.write_buffer = (unsigned) data;
    bwr.read_size = 0;
    bwr.read_consumed = 0;
    bwr.read_buffer = 0;
    res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
    if (res < 0) {
        fprintf(stderr,"binder_write: ioctl failed (%s)\n",
                strerror(errno));
    }
    return res;
}
```

首先声明一个binder_write_read结构，binder_write_read是在用户空间和内核空间传递数据的结构，定义如下：

```c
external/kernel-headers/original/uapi/linux/android/binder.h
/*
 * On 64-bit platforms where user code may run in 32-bits the driver must
 * translate the buffer (and local binder) addresses appropriately.
 */

struct binder_write_read {
	binder_size_t		write_size;	/* bytes to write */
	binder_size_t		write_consumed;	/* bytes consumed by driver */
	binder_uintptr_t	write_buffer;
	binder_size_t		read_size;	/* bytes to read */
	binder_size_t		read_consumed;	/* bytes consumed by driver */
	binder_uintptr_t	read_buffer;
};
```

在binder_write中，向binder驱动发送一个BINDER_WRITE_READ指令，带有一个binder_write_read数据结构，它里面只有write_buffer和write_size，read_size和read_buffer都为空，来看binder驱动如何处理这个请求：

```c
static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int ret;
    struct binder_proc *proc = filp->private_data;
    struct binder_thread *thread;
    unsigned int size = _IOC_SIZE(cmd);
    void __user *ubuf = (void __user *)arg;
    /*printk(KERN_INFO "binder_ioctl: %d:%d %x %lx\n", proc->pid, current->pid, cmd, arg);*/
    ret = wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
    if (ret)
        return ret;
    mutex_lock(&binder_lock);
    thread = binder_get_thread(proc);
    if (thread == NULL) {
        ret = -ENOMEM;
        goto err;
    }
    switch (cmd) {
    case BINDER_WRITE_READ: {
        struct binder_write_read bwr;
        if (size != sizeof(struct binder_write_read)) {
            ret = -EINVAL;
            goto err;
        }
        // 将用户空间的binder_write_read结构copy到内核空间的bwr变量
        if (copy_from_user(&bwr, ubuf, sizeof(bwr))) {
            ret = -EFAULT;
            goto err;
        }
        binder_debug(BINDER_DEBUG_READ_WRITE,
                 "binder: %d:%d write %ld at %08lx, read %ld at %08lx\n",
                 proc->pid, thread->pid, bwr.write_size, bwr.write_buffer,
                 bwr.read_size, bwr.read_buffer);
        if (bwr.write_size > 0) {
            ret = binder_thread_write(proc, thread, (void __user *)bwr.write_buffer, bwr.write_size, &bwr.write_consumed);
            if (ret < 0) {
                bwr.read_consumed = 0;
                if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
                    ret = -EFAULT;
                goto err;
            }
        }
        if (bwr.read_size > 0) {
            ret = binder_thread_read(proc, thread, (void __user *)bwr.read_buffer, bwr.read_size, &bwr.read_consumed, filp->f_flags & O_NONBLOCK);
            if (!list_empty(&proc->todo))
                wake_up_interruptible(&proc->wait);
            if (ret < 0) {
                if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
                    ret = -EFAULT;
                goto err;
            }
        }
        binder_debug(BINDER_DEBUG_READ_WRITE,
                 "binder: %d:%d wrote %ld of %ld, read return %ld of %ld\n",
                 proc->pid, thread->pid, bwr.write_consumed, bwr.write_size,
                 bwr.read_consumed, bwr.read_size);
        if (copy_to_user(ubuf, &bwr, sizeof(bwr))) {
            ret = -EFAULT;
            goto err;
        }
        break;
    }
    case BINDER_SET_MAX_THREADS:
        if (copy_from_user(&proc->max_threads, ubuf, sizeof(proc->max_threads))) {
            ret = -EINVAL;
            goto err;
        }
        break;
    case BINDER_SET_CONTEXT_MGR:
        if (binder_context_mgr_node != NULL) {
            printk(KERN_ERR "binder: BINDER_SET_CONTEXT_MGR already set\n");
            ret = -EBUSY;
            goto err;
        }
        if (binder_context_mgr_uid != -1) {
            if (binder_context_mgr_uid != current->cred->euid) {
                printk(KERN_ERR "binder: BINDER_SET_"
                       "CONTEXT_MGR bad uid %d != %d\n",
                       current->cred->euid,
                       binder_context_mgr_uid);
                ret = -EPERM;
                goto err;
            }
        } else
            binder_context_mgr_uid = current->cred->euid;
        binder_context_mgr_node = binder_new_node(proc, NULL, NULL);
        if (binder_context_mgr_node == NULL) {
            ret = -ENOMEM;
            goto err;
        }
        binder_context_mgr_node->local_weak_refs++;
        binder_context_mgr_node->local_strong_refs++;
        binder_context_mgr_node->has_strong_ref = 1;
        binder_context_mgr_node->has_weak_ref = 1;
        break;
    case BINDER_THREAD_EXIT:
        binder_debug(BINDER_DEBUG_THREADS, "binder: %d:%d exit\n",
                 proc->pid, thread->pid);
        binder_free_thread(proc, thread);
        thread = NULL;
        break;
    case BINDER_VERSION:
        if (size != sizeof(struct binder_version)) {
            ret = -EINVAL;
            goto err;
        }
        if (put_user(BINDER_CURRENT_PROTOCOL_VERSION, &((struct binder_version *)ubuf)->protocol_version)) {
            ret = -EINVAL;
            goto err;
        }
        break;
    default:
        ret = -EINVAL;
        goto err;
    }
    ret = 0;
err:
    if (thread)
        thread->looper &= ~BINDER_LOOPER_STATE_NEED_RETURN;
    mutex_unlock(&binder_lock);
    wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
    if (ret && ret != -ERESTARTSYS)
        printk(KERN_INFO "binder: %d:%d ioctl %x %lx returned %d\n", proc->pid, current->pid, cmd, arg, ret);
    return ret;
}
```

首先还是通过binder_get_thread去查找是否有处理的binder_thread，通过前面处理BINDER_SET_CONTEXT_MGR命令，我们知道，这里已经创建了一个binder_thread，所以会获取到它并返回。然后通过copy_from_user将用户空间的binder_write_read结构cope到内核空间的bwr变量中，然后判断它的write_size和read_size，如果它们都不为0，就分别调用binder_thread_write和binder_thread_read去分别处理写请求和读请求。从前面binder_writer函数我们知道，这里的write_szie不为0，所以会调用binder_thread_write来处理BC_ENTER_LOOP命令：

```c
int binder_thread_write(struct binder_proc *proc, struct binder_thread *thread,
            void __user *buffer, int size, signed long *consumed)
{
    uint32_t cmd;
    void __user *ptr = buffer + *consumed;
    void __user *end = buffer + size;
    while (ptr < end && thread->return_error == BR_OK) {
        if (get_user(cmd, (uint32_t __user *)ptr))
            return -EFAULT;
        ptr += sizeof(uint32_t);
        if (_IOC_NR(cmd) < ARRAY_SIZE(binder_stats.bc)) {
            binder_stats.bc[_IOC_NR(cmd)]++;
            proc->stats.bc[_IOC_NR(cmd)]++;
            thread->stats.bc[_IOC_NR(cmd)]++;
        }
        switch (cmd) {
        case BC_INCREFS:
        case BC_ACQUIRE:
        case BC_RELEASE:
        case BC_DECREFS: {
            uint32_t target;
            struct binder_ref *ref;
            const char *debug_string;
            if (get_user(target, (uint32_t __user *)ptr))
                return -EFAULT;
            ptr += sizeof(uint32_t);
            if (target == 0 && binder_context_mgr_node &&
                (cmd == BC_INCREFS || cmd == BC_ACQUIRE)) {
                ref = binder_get_ref_for_node(proc,
                           binder_context_mgr_node);
                if (ref->desc != target) {
                    binder_user_error("binder: %d:"
                        "%d tried to acquire "
                        "reference to desc 0, "
                        "got %d instead\n",
                        proc->pid, thread->pid,
                        ref->desc);
                }
            } else
                ref = binder_get_ref(proc, target);
            if (ref == NULL) {
                binder_user_error("binder: %d:%d refcou"
                    "nt change on invalid ref %d\n",
                    proc->pid, thread->pid, target);
                break;
            }
            switch (cmd) {
            case BC_INCREFS:
                debug_string = "IncRefs";
                binder_inc_ref(ref, 0, NULL);
                break;
            case BC_ACQUIRE:
                debug_string = "Acquire";
                binder_inc_ref(ref, 1, NULL);
                break;
            case BC_RELEASE:
                debug_string = "Release";
                binder_dec_ref(ref, 1);
                break;
            case BC_DECREFS:
            default:
                debug_string = "DecRefs";
                binder_dec_ref(ref, 0);
                break;
            }
            binder_debug(BINDER_DEBUG_USER_REFS,
                     "binder: %d:%d %s ref %d desc %d s %d w %d for node %d\n",
                     proc->pid, thread->pid, debug_string, ref->debug_id,
                     ref->desc, ref->strong, ref->weak, ref->node->debug_id);
            break;
        }
        case BC_INCREFS_DONE:
        case BC_ACQUIRE_DONE: {
            void __user *node_ptr;
            void *cookie;
            struct binder_node *node;
            if (get_user(node_ptr, (void * __user *)ptr))
                return -EFAULT;
            ptr += sizeof(void *);
            if (get_user(cookie, (void * __user *)ptr))
                return -EFAULT;
            ptr += sizeof(void *);
            node = binder_get_node(proc, node_ptr);
            if (node == NULL) {
                binder_user_error("binder: %d:%d "
                    "%s u%p no match\n",
                    proc->pid, thread->pid,
                    cmd == BC_INCREFS_DONE ?
                    "BC_INCREFS_DONE" :
                    "BC_ACQUIRE_DONE",
                    node_ptr);
                break;
            }
            if (cookie != node->cookie) {
                binder_user_error("binder: %d:%d %s u%p node %d"
                    " cookie mismatch %p != %p\n",
                    proc->pid, thread->pid,
                    cmd == BC_INCREFS_DONE ?
                    "BC_INCREFS_DONE" : "BC_ACQUIRE_DONE",
                    node_ptr, node->debug_id,
                    cookie, node->cookie);
                break;
            }
            if (cmd == BC_ACQUIRE_DONE) {
                if (node->pending_strong_ref == 0) {
                    binder_user_error("binder: %d:%d "
                        "BC_ACQUIRE_DONE node %d has "
                        "no pending acquire request\n",
                        proc->pid, thread->pid,
                        node->debug_id);
                    break;
                }
                node->pending_strong_ref = 0;
            } else {
                if (node->pending_weak_ref == 0) {
                    binder_user_error("binder: %d:%d "
                        "BC_INCREFS_DONE node %d has "
                        "no pending increfs request\n",
                        proc->pid, thread->pid,
                        node->debug_id);
                    break;
                }
                node->pending_weak_ref = 0;
            }
            binder_dec_node(node, cmd == BC_ACQUIRE_DONE, 0);
            binder_debug(BINDER_DEBUG_USER_REFS,
                     "binder: %d:%d %s node %d ls %d lw %d\n",
                     proc->pid, thread->pid,
                     cmd == BC_INCREFS_DONE ? "BC_INCREFS_DONE" : "BC_ACQUIRE_DONE",
                     node->debug_id, node->local_strong_refs, node->local_weak_refs);
            break;
        }
        case BC_ATTEMPT_ACQUIRE:
            printk(KERN_ERR "binder: BC_ATTEMPT_ACQUIRE not supported\n");
            return -EINVAL;
        case BC_ACQUIRE_RESULT:
            printk(KERN_ERR "binder: BC_ACQUIRE_RESULT not supported\n");
            return -EINVAL;
        case BC_FREE_BUFFER: {
            void __user *data_ptr;
            struct binder_buffer *buffer;
            if (get_user(data_ptr, (void * __user *)ptr))
                return -EFAULT;
            ptr += sizeof(void *);
            buffer = binder_buffer_lookup(proc, data_ptr);
            if (buffer == NULL) {
                binder_user_error("binder: %d:%d "
                    "BC_FREE_BUFFER u%p no match\n",
                    proc->pid, thread->pid, data_ptr);
                break;
            }
            if (!buffer->allow_user_free) {
                binder_user_error("binder: %d:%d "
                    "BC_FREE_BUFFER u%p matched "
                    "unreturned buffer\n",
                    proc->pid, thread->pid, data_ptr);
                break;
            }
            binder_debug(BINDER_DEBUG_FREE_BUFFER,
                     "binder: %d:%d BC_FREE_BUFFER u%p found buffer %d for %s transaction\n",
                     proc->pid, thread->pid, data_ptr, buffer->debug_id,
                     buffer->transaction ? "active" : "finished");
            if (buffer->transaction) {
                buffer->transaction->buffer = NULL;
                buffer->transaction = NULL;
            }
            if (buffer->async_transaction && buffer->target_node) {
                BUG_ON(!buffer->target_node->has_async_transaction);
                if (list_empty(&buffer->target_node->async_todo))
                    buffer->target_node->has_async_transaction = 0;
                else
                    list_move_tail(buffer->target_node->async_todo.next, &thread->todo);
            }
            binder_transaction_buffer_release(proc, buffer, NULL);
            binder_free_buf(proc, buffer);
            break;
        }
        case BC_TRANSACTION:
        case BC_REPLY: {
            struct binder_transaction_data tr;
            if (copy_from_user(&tr, ptr, sizeof(tr)))
                return -EFAULT;
            ptr += sizeof(tr);
            binder_transaction(proc, thread, &tr, cmd == BC_REPLY);
            break;
        }
        case BC_REGISTER_LOOPER:
            binder_debug(BINDER_DEBUG_THREADS,
                     "binder: %d:%d BC_REGISTER_LOOPER\n",
                     proc->pid, thread->pid);
            if (thread->looper & BINDER_LOOPER_STATE_ENTERED) {
                thread->looper |= BINDER_LOOPER_STATE_INVALID;
                binder_user_error("binder: %d:%d ERROR:"
                    " BC_REGISTER_LOOPER called "
                    "after BC_ENTER_LOOPER\n",
                    proc->pid, thread->pid);
            } else if (proc->requested_threads == 0) {
                thread->looper |= BINDER_LOOPER_STATE_INVALID;
                binder_user_error("binder: %d:%d ERROR:"
                    " BC_REGISTER_LOOPER called "
                    "without request\n",
                    proc->pid, thread->pid);
            } else {
                proc->requested_threads--;
                proc->requested_threads_started++;
            }
            thread->looper |= BINDER_LOOPER_STATE_REGISTERED;
            break;
        case BC_ENTER_LOOPER:
            binder_debug(BINDER_DEBUG_THREADS,
                     "binder: %d:%d BC_ENTER_LOOPER\n",
                     proc->pid, thread->pid);
            if (thread->looper & BINDER_LOOPER_STATE_REGISTERED) {
                thread->looper |= BINDER_LOOPER_STATE_INVALID;
                binder_user_error("binder: %d:%d ERROR:"
                    " BC_ENTER_LOOPER called after "
                    "BC_REGISTER_LOOPER\n",
                    proc->pid, thread->pid);
            }
            thread->looper |= BINDER_LOOPER_STATE_ENTERED;
            break;
        case BC_EXIT_LOOPER:
            binder_debug(BINDER_DEBUG_THREADS,
                     "binder: %d:%d BC_EXIT_LOOPER\n",
                     proc->pid, thread->pid);
            thread->looper |= BINDER_LOOPER_STATE_EXITED;
            break;
        case BC_REQUEST_DEATH_NOTIFICATION:
        case BC_CLEAR_DEATH_NOTIFICATION: {
            uint32_t target;
            void __user *cookie;
            struct binder_ref *ref;
            struct binder_ref_death *death;
            if (get_user(target, (uint32_t __user *)ptr))
                return -EFAULT;
            ptr += sizeof(uint32_t);
            if (get_user(cookie, (void __user * __user *)ptr))
                return -EFAULT;
            ptr += sizeof(void *);
            ref = binder_get_ref(proc, target);
            if (ref == NULL) {
                binder_user_error("binder: %d:%d %s "
                    "invalid ref %d\n",
                    proc->pid, thread->pid,
                    cmd == BC_REQUEST_DEATH_NOTIFICATION ?
                    "BC_REQUEST_DEATH_NOTIFICATION" :
                    "BC_CLEAR_DEATH_NOTIFICATION",
                    target);
                break;
            }
            binder_debug(BINDER_DEBUG_DEATH_NOTIFICATION,
                     "binder: %d:%d %s %p ref %d desc %d s %d w %d for node %d\n",
                     proc->pid, thread->pid,
                     cmd == BC_REQUEST_DEATH_NOTIFICATION ?
                     "BC_REQUEST_DEATH_NOTIFICATION" :
                     "BC_CLEAR_DEATH_NOTIFICATION",
                     cookie, ref->debug_id, ref->desc,
                     ref->strong, ref->weak, ref->node->debug_id);
            if (cmd == BC_REQUEST_DEATH_NOTIFICATION) {
                if (ref->death) {
                    binder_user_error("binder: %d:%"
                        "d BC_REQUEST_DEATH_NOTI"
                        "FICATION death notific"
                        "ation already set\n",
                        proc->pid, thread->pid);
                    break;
                }
                death = kzalloc(sizeof(*death), GFP_KERNEL);
                if (death == NULL) {
                    thread->return_error = BR_ERROR;
                    binder_debug(BINDER_DEBUG_FAILED_TRANSACTION,
                             "binder: %d:%d "
                             "BC_REQUEST_DEATH_NOTIFICATION failed\n",
                             proc->pid, thread->pid);
                    break;
                }
                binder_stats_created(BINDER_STAT_DEATH);
                INIT_LIST_HEAD(&death->work.entry);
                death->cookie = cookie;
                ref->death = death;
                if (ref->node->proc == NULL) {
                    ref->death->work.type = BINDER_WORK_DEAD_BINDER;
                    if (thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED)) {
                        list_add_tail(&ref->death->work.entry, &thread->todo);
                    } else {
                        list_add_tail(&ref->death->work.entry, &proc->todo);
                        wake_up_interruptible(&proc->wait);
                    }
                }
            } else {
                if (ref->death == NULL) {
                    binder_user_error("binder: %d:%"
                        "d BC_CLEAR_DEATH_NOTIFI"
                        "CATION death notificat"
                        "ion not active\n",
                        proc->pid, thread->pid);
                    break;
                }
                death = ref->death;
                if (death->cookie != cookie) {
                    binder_user_error("binder: %d:%"
                        "d BC_CLEAR_DEATH_NOTIFI"
                        "CATION death notificat"
                        "ion cookie mismatch "
                        "%p != %p\n",
                        proc->pid, thread->pid,
                        death->cookie, cookie);
                    break;
                }
                ref->death = NULL;
                if (list_empty(&death->work.entry)) {
                    death->work.type = BINDER_WORK_CLEAR_DEATH_NOTIFICATION;
                    if (thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED)) {
                        list_add_tail(&death->work.entry, &thread->todo);
                    } else {
                        list_add_tail(&death->work.entry, &proc->todo);
                        wake_up_interruptible(&proc->wait);
                    }
                } else {
                    BUG_ON(death->work.type != BINDER_WORK_DEAD_BINDER);
                    death->work.type = BINDER_WORK_DEAD_BINDER_AND_CLEAR;
                }
            }
        } break;
        case BC_DEAD_BINDER_DONE: {
            struct binder_work *w;
            void __user *cookie;
            struct binder_ref_death *death = NULL;
            if (get_user(cookie, (void __user * __user *)ptr))
                return -EFAULT;
            ptr += sizeof(void *);
            list_for_each_entry(w, &proc->delivered_death, entry) {
                struct binder_ref_death *tmp_death = container_of(w, struct binder_ref_death, work);
                if (tmp_death->cookie == cookie) {
                    death = tmp_death;
                    break;
                }
            }
            binder_debug(BINDER_DEBUG_DEAD_BINDER,
                     "binder: %d:%d BC_DEAD_BINDER_DONE %p found %p\n",
                     proc->pid, thread->pid, cookie, death);
            if (death == NULL) {
                binder_user_error("binder: %d:%d BC_DEAD"
                    "_BINDER_DONE %p not found\n",
                    proc->pid, thread->pid, cookie);
                break;
            }
            list_del_init(&death->work.entry);
            if (death->work.type == BINDER_WORK_DEAD_BINDER_AND_CLEAR) {
                death->work.type = BINDER_WORK_CLEAR_DEATH_NOTIFICATION;
                if (thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED)) {
                    list_add_tail(&death->work.entry, &thread->todo);
                } else {
                    list_add_tail(&death->work.entry, &proc->todo);
                    wake_up_interruptible(&proc->wait);
                }
            }
        } break;
        default:
            printk(KERN_ERR "binder: %d:%d unknown command %d\n",
                   proc->pid, thread->pid, cmd);
            return -EINVAL;
        }
        *consumed = ptr - buffer;
    }
    return 0;
}
```

首先从binder_write_read数据结构中的writer_buffer取出BC_ENTER_LOOPER命令，然后将binder_thread的looper设置位BINDER_LOOPER_STATE_ENTERED，表示进入到looper循环当中了。处理完BC_ENTER_LOOPER命令后，在binder_looper方法中接着向binder驱动发送BINDER_WRITE_READ，这次带有的binder_write_read参数中，只有read_size不为0，write_size为0，通过上面的知识我们知道，这里会调用binder_thread_read来处理：

```c
static int binder_thread_read(struct binder_proc *proc,
                  struct binder_thread *thread,
                  void  __user *buffer, int size,
                  signed long *consumed, int non_block)
{
    void __user *ptr = buffer + *consumed;
    void __user *end = buffer + size;
    int ret = 0;
    int wait_for_proc_work;
    if (*consumed == 0) {
        if (put_user(BR_NOOP, (uint32_t __user *)ptr))
            return -EFAULT;
        ptr += sizeof(uint32_t);
    }
retry:
    wait_for_proc_work = thread->transaction_stack == NULL &&
                list_empty(&thread->todo);
    if (thread->return_error != BR_OK && ptr < end) {
        if (thread->return_error2 != BR_OK) {
            if (put_user(thread->return_error2, (uint32_t __user *)ptr))
                return -EFAULT;
            ptr += sizeof(uint32_t);
            if (ptr == end)
                goto done;
            thread->return_error2 = BR_OK;
        }
        if (put_user(thread->return_error, (uint32_t __user *)ptr))
            return -EFAULT;
        ptr += sizeof(uint32_t);
        thread->return_error = BR_OK;
        goto done;
    }
    thread->looper |= BINDER_LOOPER_STATE_WAITING;
    if (wait_for_proc_work)
        proc->ready_threads++;
    mutex_unlock(&binder_lock);
    if (wait_for_proc_work) {
        if (!(thread->looper & (BINDER_LOOPER_STATE_REGISTERED |
                    BINDER_LOOPER_STATE_ENTERED))) {
            binder_user_error("binder: %d:%d ERROR: Thread waiting "
                "for process work before calling BC_REGISTER_"
                "LOOPER or BC_ENTER_LOOPER (state %x)\n",
                proc->pid, thread->pid, thread->looper);
            wait_event_interruptible(binder_user_error_wait,
                         binder_stop_on_user_error < 2);
        }
        binder_set_nice(proc->default_priority);
        if (non_block) {
            if (!binder_has_proc_work(proc, thread))
                ret = -EAGAIN;
        } else
            ret = wait_event_interruptible_exclusive(proc->wait, binder_has_proc_work(proc, thread));
    } else {
        if (non_block) {
            if (!binder_has_thread_work(thread))
                ret = -EAGAIN;
        } else
            ret = wait_event_interruptible(thread->wait, binder_has_thread_work(thread));
    }
    mutex_lock(&binder_lock);
    if (wait_for_proc_work)
        proc->ready_threads--;
    thread->looper &= ~BINDER_LOOPER_STATE_WAITING;
    if (ret)
        return ret;
    while (1) {
        uint32_t cmd;
        struct binder_transaction_data tr;
        struct binder_work *w;
        struct binder_transaction *t = NULL;
        if (!list_empty(&thread->todo))
            w = list_first_entry(&thread->todo, struct binder_work, entry);
        else if (!list_empty(&proc->todo) && wait_for_proc_work)
            w = list_first_entry(&proc->todo, struct binder_work, entry);
        else {
            if (ptr - buffer == 4 && !(thread->looper & BINDER_LOOPER_STATE_NEED_RETURN)) /* no data added */
                goto retry;
            break;
        }
        if (end - ptr < sizeof(tr) + 4)
            break;
        switch (w->type) {
        case BINDER_WORK_TRANSACTION: {
            t = container_of(w, struct binder_transaction, work);
        } break;
        case BINDER_WORK_TRANSACTION_COMPLETE: {
            cmd = BR_TRANSACTION_COMPLETE;
            if (put_user(cmd, (uint32_t __user *)ptr))
                return -EFAULT;
            ptr += sizeof(uint32_t);
            binder_stat_br(proc, thread, cmd);
            binder_debug(BINDER_DEBUG_TRANSACTION_COMPLETE,
                     "binder: %d:%d BR_TRANSACTION_COMPLETE\n",
                     proc->pid, thread->pid);
            list_del(&w->entry);
            kfree(w);
            binder_stats_deleted(BINDER_STAT_TRANSACTION_COMPLETE);
        } break;
        case BINDER_WORK_NODE: {
            struct binder_node *node = container_of(w, struct binder_node, work);
            uint32_t cmd = BR_NOOP;
            const char *cmd_name;
            int strong = node->internal_strong_refs || node->local_strong_refs;
            int weak = !hlist_empty(&node->refs) || node->local_weak_refs || strong;
            if (weak && !node->has_weak_ref) {
                cmd = BR_INCREFS;
                cmd_name = "BR_INCREFS";
                node->has_weak_ref = 1;
                node->pending_weak_ref = 1;
                node->local_weak_refs++;
            } else if (strong && !node->has_strong_ref) {
                cmd = BR_ACQUIRE;
                cmd_name = "BR_ACQUIRE";
                node->has_strong_ref = 1;
                node->pending_strong_ref = 1;
                node->local_strong_refs++;
            } else if (!strong && node->has_strong_ref) {
                cmd = BR_RELEASE;
                cmd_name = "BR_RELEASE";
                node->has_strong_ref = 0;
            } else if (!weak && node->has_weak_ref) {
                cmd = BR_DECREFS;
                cmd_name = "BR_DECREFS";
                node->has_weak_ref = 0;
            }
            if (cmd != BR_NOOP) {
                if (put_user(cmd, (uint32_t __user *)ptr))
                    return -EFAULT;
                ptr += sizeof(uint32_t);
                if (put_user(node->ptr, (void * __user *)ptr))
                    return -EFAULT;
                ptr += sizeof(void *);
                if (put_user(node->cookie, (void * __user *)ptr))
                    return -EFAULT;
                ptr += sizeof(void *);
                binder_stat_br(proc, thread, cmd);
                binder_debug(BINDER_DEBUG_USER_REFS,
                         "binder: %d:%d %s %d u%p c%p\n",
                         proc->pid, thread->pid, cmd_name, node->debug_id, node->ptr, node->cookie);
            } else {
                list_del_init(&w->entry);
                if (!weak && !strong) {
                    binder_debug(BINDER_DEBUG_INTERNAL_REFS,
                             "binder: %d:%d node %d u%p c%p deleted\n",
                             proc->pid, thread->pid, node->debug_id,
                             node->ptr, node->cookie);
                    rb_erase(&node->rb_node, &proc->nodes);
                    kfree(node);
                    binder_stats_deleted(BINDER_STAT_NODE);
                } else {
                    binder_debug(BINDER_DEBUG_INTERNAL_REFS,
                             "binder: %d:%d node %d u%p c%p state unchanged\n",
                             proc->pid, thread->pid, node->debug_id, node->ptr,
                             node->cookie);
                }
            }
        } break;
        case BINDER_WORK_DEAD_BINDER:
        case BINDER_WORK_DEAD_BINDER_AND_CLEAR:
        case BINDER_WORK_CLEAR_DEATH_NOTIFICATION: {
            struct binder_ref_death *death;
            uint32_t cmd;
            death = container_of(w, struct binder_ref_death, work);
            if (w->type == BINDER_WORK_CLEAR_DEATH_NOTIFICATION)
                cmd = BR_CLEAR_DEATH_NOTIFICATION_DONE;
            else
                cmd = BR_DEAD_BINDER;
            if (put_user(cmd, (uint32_t __user *)ptr))
                return -EFAULT;
            ptr += sizeof(uint32_t);
            if (put_user(death->cookie, (void * __user *)ptr))
                return -EFAULT;
            ptr += sizeof(void *);
            binder_debug(BINDER_DEBUG_DEATH_NOTIFICATION,
                     "binder: %d:%d %s %p\n",
                      proc->pid, thread->pid,
                      cmd == BR_DEAD_BINDER ?
                      "BR_DEAD_BINDER" :
                      "BR_CLEAR_DEATH_NOTIFICATION_DONE",
                      death->cookie);
            if (w->type == BINDER_WORK_CLEAR_DEATH_NOTIFICATION) {
                list_del(&w->entry);
                kfree(death);
                binder_stats_deleted(BINDER_STAT_DEATH);
            } else
                list_move(&w->entry, &proc->delivered_death);
            if (cmd == BR_DEAD_BINDER)
                goto done; /* DEAD_BINDER notifications can cause transactions */
        } break;
        }
        if (!t)
            continue;
        BUG_ON(t->buffer == NULL);
        if (t->buffer->target_node) {
            struct binder_node *target_node = t->buffer->target_node;
            tr.target.ptr = target_node->ptr;
            tr.cookie =  target_node->cookie;
            t->saved_priority = task_nice(current);
            if (t->priority < target_node->min_priority &&
                !(t->flags & TF_ONE_WAY))
                binder_set_nice(t->priority);
            else if (!(t->flags & TF_ONE_WAY) ||
                 t->saved_priority > target_node->min_priority)
                binder_set_nice(target_node->min_priority);
            cmd = BR_TRANSACTION;
        } else {
            tr.target.ptr = NULL;
            tr.cookie = NULL;
            cmd = BR_REPLY;
        }
        tr.code = t->code;
        tr.flags = t->flags;
        tr.sender_euid = t->sender_euid;
        if (t->from) {
            struct task_struct *sender = t->from->proc->tsk;
            tr.sender_pid = task_tgid_nr_ns(sender,
                            current->nsproxy->pid_ns);
        } else {
            tr.sender_pid = 0;
        }
        tr.data_size = t->buffer->data_size;
        tr.offsets_size = t->buffer->offsets_size;
        tr.data.ptr.buffer = (void *)t->buffer->data +
                    proc->user_buffer_offset;
        tr.data.ptr.offsets = tr.data.ptr.buffer +
                    ALIGN(t->buffer->data_size,
                        sizeof(void *));
        if (put_user(cmd, (uint32_t __user *)ptr))
            return -EFAULT;
        ptr += sizeof(uint32_t);
        if (copy_to_user(ptr, &tr, sizeof(tr)))
            return -EFAULT;
        ptr += sizeof(tr);
        binder_stat_br(proc, thread, cmd);
        binder_debug(BINDER_DEBUG_TRANSACTION,
                 "binder: %d:%d %s %d %d:%d, cmd %d"
                 "size %zd-%zd ptr %p-%p\n",
                 proc->pid, thread->pid,
                 (cmd == BR_TRANSACTION) ? "BR_TRANSACTION" :
                 "BR_REPLY",
                 t->debug_id, t->from ? t->from->proc->pid : 0,
                 t->from ? t->from->pid : 0, cmd,
                 t->buffer->data_size, t->buffer->offsets_size,
                 tr.data.ptr.buffer, tr.data.ptr.offsets);
        list_del(&t->work.entry);
        t->buffer->allow_user_free = 1;
        if (cmd == BR_TRANSACTION && !(t->flags & TF_ONE_WAY)) {
            t->to_parent = thread->transaction_stack;
            t->to_thread = thread;
            thread->transaction_stack = t;
        } else {
            t->buffer->transaction = NULL;
            kfree(t);
            binder_stats_deleted(BINDER_STAT_TRANSACTION);
        }
        break;
    }
done:
    *consumed = ptr - buffer;
    if (proc->requested_threads + proc->ready_threads == 0 &&
        proc->requested_threads_started < proc->max_threads &&
        (thread->looper & (BINDER_LOOPER_STATE_REGISTERED |
         BINDER_LOOPER_STATE_ENTERED)) /* the user-space code fails to */
         /*spawn a new thread if we leave this out */) {
        proc->requested_threads++;
        binder_debug(BINDER_DEBUG_THREADS,
                 "binder: %d:%d BR_SPAWN_LOOPER\n",
                 proc->pid, thread->pid);
        if (put_user(BR_SPAWN_LOOPER, (uint32_t __user *)buffer))
            return -EFAULT;
    }
    return 0;
}
```

因为在binder_loop中设置的read_consumed等于0，所以这里会先往read_buffer写入一个BR_NOOP命令。由于刚之前创建的binder_thread中的transaction_stack和todo列表都是空，所以这里的wait_for_proc_work为true，表示需要等待客户端的请求，并将binder_thread的looper置或上BINDER_LOOPER_STATE_WAITING，由于之前执行BC_ENTER_LOOPER命令，所以现在looper的值BINDER_LOOPER_STATE_ENTERED | BINDER_LOOPER_STATE_WAITING。由于在打开/dev/binder中，并没有设置O_NONBLOCK标志，所以这里的non_block为false。最后这里调用wait_event_freezable_exclusive等待客户端的请求。

## ProcessState、IPCThreadState

ProcessState:一个进程只有一个引用负责管理IPCThreadState，在service.cpp中

IPCThreadState是LocalThread，每个线程只有一个并负责binder的通信

SystemService 启动ActivityManagerService（AMS）

SystemService为系统服务开启并保存，SystemService是单独的进程
ActivityManagerService将某些common服务放到自己的map中（可以直接在本进程获取）并管理4大组件

问题Service怎么注册的binder
ActivityThread$ApplicationThread extends IApplicationThread.Stub 接收跨进程信息，（scheduleCreateService方法）
ActivityService中realStartServiceLocked方法在两个地方调用1. attachApplicationLocked， 2. bringUpServiceLocked
attachApplicationLocked在ActivityManagerService的attachApplication方法调用，该方法继承自IActivityManager.Stub



ActivityManager 最终会调用AMS的对应方法,ActivityManagerService(AMS), ActivityThread