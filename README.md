# securityHandover

## 安全管理系统（taroManage）

身份认证管理和资源权限管理

项目地址：[后端](https://github.com/theChildinus/tarobackend )、[前端]( https://github.com/theChildinus/tarofrontend )、 [fabric服务](https://github.com/theChildinus/fabric-service-client)

论文：结合区块链的物联网服务系统安全保障方案的研究与设计

项目部署：实验室服务器Ubuntu16-XIAN01 、西安授时中心（单独的linux笔记本上）

## 目前研究进展：

安全：可信计算、内存监控、内存取证、运行时验证

### 内存监控系统

针对虚拟机内存进行监控（libvmi （内存获取）+ volatility（内存重构） ） 

[项目环境部署](https://github.com/theChildinus/JavaMemory)：实验室服务器Ubuntu16-XIAN02、linux笔记本

项目代码：./内存监控系统/Vmsystem.tar.gz

### 可信计算

关于SGX和TPM的信任链扩展，保证平台的可信

SGX论文: 可信物联网数据采集平台的研究与实现（平台可信+区块链上链可信）

项目部署：linux笔记本

### 内存取证

针对虚拟机的内存获取：C语言+java语言 

项目地址：https://github.com/theChildinus/JavaMemory

https://github.com/theChildinus/JavaMemory/blob/master/Review.md

论文：C语言 -- 论文 面向虚拟化的物联网服务系统运行时验证方案的研究和实现（linux_runtime.py）

Java语言 -- 基于服务容器的服务语义重构(linux_memory_analyze.py)

项目部署：linux笔记本上：/home/../Project/JavaMemory/volatility-2.6 (直接打开pycharm就可以看到)

### 运行时验证

论文：物联网服务系统运行时验证系统的研究与实现

[项目地址](https://github.com/theChildinus/IoTEventMonitorPlatform)

项目部署：linux笔记本：/home/../SGXProject/IotProjects/IoTEventMonitorPlatfrom (直接打开CLion就可以看到)

### 我的研究

TPM结合IMA +docker上的内存取证+运行时状态机修改