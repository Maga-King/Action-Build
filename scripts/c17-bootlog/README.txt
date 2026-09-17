这是给一加13移植C17临时排错用的 不是日用内核

在 KernelSU-Next 的 Build All OnePlus Kernels 里选 oneplus_13_b
保持 FAST_BUILD 开启 RESUBLEVEL 留空
C17_BOOTLOG 选 permissive 就是锁定全局宽容的诊断版
选 enforcing 是只加日志 不改变原本的 SELinux 行为
选 off 则不会应用这里的内核修改
宽容版 setenforce 1 也不会切回严格 getenforce 会如实显示 Permissive
请排错后刷回正常内核 不要作为长期使用版本
SELinux 策略编译失败或加载失败不会因为宽容而自动修好

源码必须真的是6.6.118 不用改版本号冒充
日志缓冲扩大到4MiB
只在检测到已实测的0x240000 ramoops布局时调整该预留区
改为256KiB崩溃记录 1MiB控制台 1MiB用户态记录
不改物理地址 不扩大占用 不写任何裸分区
布局不匹配就保留原状 并在内核日志中说明
需要刷入后检查 C17_BOOTLOG 标记和 /sys/module/ramoops/parameters
编译成功不等于这些运行时检查已经通过
新旧布局不同 第一轮旧日志可能无法解码 之后请保持同一个诊断内核测试
正常重启和panic尝试记录 硬断电或引导程序清空内存仍可能丢日志

AnyKernel3 是内核包 C17-BootLog 是构建证据和辅助工具 不要混淆
C17-Metadata-Log-Collector-optional.zip 是可选KernelSU日志模块
安装后在 post-fs-data 后备份当时可读取的日志 不轮询 不清理旧日志
普通文件存在 /metadata/c17-bootlogs 下 文件名包含随机串
实测这台metadata总共约62MiB 现在只剩约17MiB 不能敞开写
单次采集控制在约3MiB以内 存档总预算6MiB 并给metadata留至少12MiB
空间不够就跳过 不自动删除你的记录 最多4个随机目录
为控制占用 pstore最多复制2.25MiB 其余日志只留尾部摘要
这次拿到日志后请及时复制到电脑 不要把metadata当长期日志仓库
模块需要安装在返回后能启动的主系统 它不能在未解锁data之前运行
手工也可以 root执行 sh collect.sh 结束后会输出保存目录
查看 errors.txt 和 result.txt 别把空文件当作抓取成功
这只是第二条存档路径 不能保证SELinux加载前就把日志写进metadata
如果需要覆盖那么早的失败阶段 还需要单独适配first-stage init或恢复环境
本次不修改boot ramdisk 不修改DTBO 不自动刷机 不自动重启

失败后尽量不要连续重启 回主系统第一时间复制 /sys/fs/pstore
硬断电过的这轮可能已经没有日志 重试前先确认诊断内核真的生效
