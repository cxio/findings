# 节点发现服务（findings）

## 前言

提供各种类型节点的登记注册，维护一个节点连系信息的暂存池，向请求目标类型节点信息的用户提供连系清单。同时，作为P2P网络的基础设施，为新节点的加入提供 `NAT打洞` 服务支持，因为findings已经是一个网络，所以多机协作无需双IP配置。

一台服务器维护的节点信息包含同类节点（`findings`）、依自身配置支持的各种区块链应用节点，以及数据驿站默认包含的 `depots/archives` 和 `depots/blockqs` 公共服务节点。

通常，应用节点会启动一个自己的findings服务器，该服务器通过多种方式搜寻其它findings服务节点进行组网。如果存在已知的公共findings节点，组网会很快，否则可能是一个比较耗时的过程，如果需要findings实时可用，可以运行一个长期在线的服务器。

服务器会向请求节点信息的区块链应用公布一个对应区块链的地址，用于接收可能有的奖励。除了 `depots/archives, blockqs` 公共服务节点会被普遍支持外，对于不同的区块链应用可能有所选择。服务器通常会先声明自己支持的区块链名称。



## 用法



## 性能



## 附：网络的连通性

### 暴力发现

传统上，P2P网络有一个致命的单机故障点：即新节点上线连系其它节点的那个中介。目前的解决办法有几个，比如在App发布时加入几个主要节点的IP，或者通过专用的聊天频道获取，但实际上这些都可以被封堵，因为目标很清楚。

findings是一个网络，通过大众化的利益驱动模式发展（低成本且可能有收益），如果网络运行正常，假以时日，以万为单位的服务器数量是可能的。用IP遍历轮询的方式发现目标节点，在传统的网络环境下不可行（目标太小且耗时过长），但量变到质变，假设findings服务器已达10万规模，那这个网络就是一个巨大的目标了。

findings服务器可以仅仅是一台旧手机或树莓派，它们可以长期挂机在线，如果侦测目标十分巨大，**暴力发现** 的逻辑就是可行的。目标大可以提高命中率，长时间的在线可以与用户的使用时间脱钩，这两者的效果正好是叠加的。

网络空间确实巨大，简单的暴力发现依然困难（虽然不再是不可接受），IPv6新版地址的出现加剧了这种困难。但事实上可能并没有那么糟糕：人们使用IP地址是有规律的，IP地址在真实世界里的分布并不真的是随机，而是有「簇群」的特征，这些簇群的IP地址通常是连续的。这样，IP地址的遍历还是可以有的放矢。

如果一个findings服务器曾经连上过网络，一个简单的算法可以是以曾经的历史IP为原点，前后延伸遍历。


### 工作量屏障

#### 动态端口

对抗网络阻断攻击的一个方法是采用动态端口，但服务器端的动态端口必须是可预测的，否则用户也没法知道如何连接。这种预测端口的算法可以加入工作量的逻辑，迫使攻击者也需要付出同样的代价。

每个服务器的端口变化规律可以不一样，这与它们的IP相关，目标端口会在一定的时间段（如1小时）内保持不变，以获得确定性。

**算法示意：**

```go
var IP          net.IP      // 服务器地址
var dffMax      [32]byte    // 难度常数（00FFFFFFFF00000000...）

// App配置项，约1个月变化频度
var start       int64 = GetConfig("start")      // 起点时间戳（毫秒），让时间段随机。
var rndBase     int64 = GetConfig("rndBase")    // 随机数种子值，让端口取材随机。
var difficulty  int64 = GetConfig("difficulty") // 难度系数（>1），约消耗普通单机1秒左右。

var target      = dffMax / difficulty  // 目标难度
var port int64  = 0                    // 端口号存储（素材）
var rndMax      = 1<<63-1              // 随机值边界

// 随机值确定性
rand.Seed( rndBase )

for {
    // 当前真实时间（毫秒）
    now := time.Now().UnixNano() / 1000000

    // 换算到时间段
    // 1小时内不变，逐时递增
    time := (now - start) % (3600*1000)

    // 端口值素材
    port = rand.Intn(rndMax)

    // 随机性
    rnd := Hash32( IP + time + port )

    if rnd < target {
        break   // 满足目标难度
    }
}
return port % 64000 + 1024   // 目标端口，不占用系统级
```

也就是说，目标服务器的端口在1个小时内是稳定的，但用户或攻击者必须付出一定的工作量才能获知这个端口值。如果控制目标难度在适当的水平，作为普通用户的开销是可以接受的（甚至不易觉察），但对攻击者而言，阻断大量的目标服务器就需要大量的工作量运算。

当然，这些工作量其实是可以预先计算的，但这需要攻击者预先获取目标App的配置，因此App保持对起点时间和随机种子的适度更新是必要的，如1个月更新一次（难度系数的改变受制于当前计算机硬件能力，没有随意性）。

> **注：**<br>
> 为了避免计算出来的目标端口与本机上其它服务的端口冲突，这里预作一个约定：<br>
> **目标端口之后的连续2两个端口号为备用端口**。如计算得到的端口号是 `2345`，则 `2346` 和 `2347` 为备用端口。


#### 握手特征消除

上面算法中满足目标难度的哈希序列（rnd）实际上还可用作混淆密钥，隐藏初始数据包的握手信息：再哈希一次，然后与数据包做异或位计算。服务端接收到数据包后，用同样的算法再异或一次即可获得原始的信息。


### 端口混入

这是突破网络阻断最下策的一种方式。如果攻击者有能力屏蔽所有非标准端口的数据包（比如白名单），这时可能就只有采用端口混入的方式了。因为并不是所有的公网IP都会提供那些标准端口的服务，所以一台并不提供 https 服务的公网主机实际上可以用 443 端口提供 findings 服务。

这需要拥有公网IP的主机们共同努力，才能让这种方式有一定的可行性。毫无疑问，这是一种极端情况，暂不涉及。

#### 混淆码的工作量

因为采用明确的端口，所以混淆码需要另外获取。这里依然可以加入工作量屏障的因素，比如要求迭代10万次，获取最低哈希值作为混淆码。算法略。
