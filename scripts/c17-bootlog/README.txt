这版是 OnePlus 13 真正 6.6.118 的 C17LOG3 日志内核 不是开机修复保证

和第二版不同 这版不再提供强制宽容
workflow 的 C17_BOOTLOG 选 enforcing 只开日志 不修改 SELinux 的正常行为
源码检查会核对 security.h hooks.c selinuxfs.c 三个文件前后哈希
发现上一版强制宽容补丁就停止编译 防止拿旧源码混着打包
off 仍然是完全不应用我们的诊断补丁

沿用第二版实机通过的早期 ramoops 后端 在用户态 init 之前接管现有 DT 节点
内核日志缓冲是 4MiB 预留内存仍是原来的 0x240000 不换地址也不扩大
里面分成 256KiB 重启或崩溃转储 1MiB console 1MiB pmsg
不删高通模块 不改 DTBO 不改 ramdisk 不写任何裸分区
布局和芯片不符合检查条件就不接管

第三版增加两个日志保存措施
正常 kernel_restart 在设备关闭前先转储一次 原来最后阶段的转储也保留
ramoops 收到 dmesg 转储后 对现有缓存映射的日志区域执行 ARM64 cache clean to PoC
只在转储事件触发 没有轮询 不在每条 printk 后扫描整个缓冲
这是补足保存路径 不是断言第二版一定因为缓存丢日志
断电 引导程序清空内存 硬复位不走内核路径 连续多次启动覆盖旧记录 都仍可能丢日志

编译选 oneplus_13_b FAST_BUILD 打开 RESUBLEVEL 留空
内核补丁 测试 编译后的配置和 SELinux 哈希都保存在 C17-BootLog 构建产物里
AnyKernel3 才是内核安装包 C17-BootLog 是证据和工具 两个别弄反
编译通过不代表刷入成功 也不代表已经验证跨重启日志

刷入后先进入能正常启动的系统 不要直接开始反复撞 fastboot
电脑上运行
python validate_c17_bootlog_device.py --adb C:/adb-fastboot/adb.exe --serial 设备序列号 --out 新目录 --expect-v3 --su --write-marker
已经是 root adb 可以去掉 --su 脚本本身不重启 adbd
检查包括实际内核版本 Enforcing 预留内存布局 驱动归属 以及 ramoops 早于 init 的时间戳
早期日志被覆盖看不到时会报未知 不会当成通过

确认第一轮检查通过后 手动正常重启一次 保持同一个内核和系统
python validate_c17_bootlog_device.py --adb C:/adb-fastboot/adb.exe --serial 设备序列号 --out 另一个新目录 --expect-v3 --su --previous-marker 上一目录/marker.json
需要 boot_id 改变 且上一轮 marker 出现在 pstore 才算普通重启留存通过
中途换内核会报无法比较 遇到额外异常重启也不能当成干净的对照测试
验证脚本不刷机 不自动重启 不删 pstore 不改策略
确认留存可用后再测试失败的 C17 返回时也保留这个内核 尽快采集

可选 C17-Metadata-Log-Collector-optional.zip 是 KernelSU 备份模块
post-fs-data 后把已有日志存入 /metadata/c17-bootlogs 下的随机目录
必须 metadata 已挂载且有足够空间 一次约 3MiB 总预算 6MiB 保留至少 12MiB 空间
不覆盖旧记录 不自动删文件 不轮询 空间不足就停止
它不能覆盖 post-fs-data 之前的失败 不能保证 DSU metadata 已经挂载
也可以 root 手动执行 collect.sh 看 errors.txt 和 result.txt 别把空文件当成功

安全边界
这版不自动切换 DSU 不自动刷机 不修改主系统 fstab 或 vold
不制造 panic 不打开 EDL 不更换 SELinux mapping 不伪造 SDK
如果仍抓不到 先保留证据 再分清是没写进 RAM 还是下一次引导清掉了 RAM
