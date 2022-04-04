/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_IPV6 = 0x86DD;
const bit<16> TYPE_ARP = 0x0806;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

//HEADERS 部分定义报文的各类报头的格式

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<128> ip6Addr_t;

//以太网帧头部
header ethernet_t {
    macAddr_t dstAddr;	//MAC destination
    macAddr_t srcAddr;	//MAC source
    bit<16>   etherType;	//ipv4:0x0800 ARP:0x0806 ipv6:0x86DD
}

//ipv4帧头部
header ipv4_t {
    bit<4>    version;	//ip协议号
    bit<4>    ihl;	//首部长度
    bit<8>    diffserv;	//区分服务
    bit<16>   totalLen;	//总长度 首部与数据之和
    bit<16>   identification;	//报文标识
    bit<3>    flags;	//无效 允许分片 有后续分片
    bit<13>   fragOffset;	//片位移
    bit<8>    ttl;	//生存时间
    bit<8>    protocol;	//协议
    bit<16>   hdrChecksum;	//首部校验和
    ip4Addr_t srcAddr;	//源ip
    ip4Addr_t dstAddr;	//目的ip
}

//元数据 用于携带数据和配置信息
struct metadata {
    /* empty */
}

//包头部
struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

//PARSER 部分描述如何处理所收到报文的包头，这包括包头的解析顺序，从报文中要提取的包头和字段等

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    //transition 的初态，仅考虑以太网帧，所以直接进入以太网帧的解析状态
    state start {
        transition ethernet_state;
    }
    
    //自定义状态，用于解析以太网帧
    state ethernet_state {
        packet.extract(hdr.ethernet);	//提取包中的以太网帧头
        //根据以太网帧的 etherType 字段决定 transition 的下个状态
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: ipv4_state;	//0x800为ipv4
            default: reject;	//其余情况拒绝抛出
        }
    }
    
    //自定义状态，用于解析ipv4
    state ipv4_state {
        packet.extract(hdr.ipv4);	//继续提取ipv4头
        transition accept;	//接受
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

//INGRESS PROCESSING 部分主要用于处理包头的字段以及元数据，是数据包进入的处理
//根据 table 将用于定义的 key 和 action 关联，从而实现数据包的转发或丢弃
//apply 为执行入口

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        //将要丢弃的包标记为丢弃
        mark_to_drop(standard_metadata);
    }

    //ipv4 转发动作
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        //选择数据包的输出端口
        standard_metadata.egress_spec = port;
        //更改以太网帧头的 MAC 目标地址及源地址
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        //修改 ipv4 报头的生存时间
        hdr.ipv4.ttl = hdr.ipv4.ttl-1;
    }

    table ipv4_lpm {
        key = {
            //lpm是最长前缀匹配，exact完全匹配，ternary三元匹配
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;	//转发
            drop;	//丢弃
            NoAction;	//空动作
        }
        size = 1024;	//流表项容量
        default_action = drop();	//table miss 则丢弃
    }

    apply {
        //如果 ipv4 有效，则执行 ipv4 的匹配 table
        if (hdr.ipv4.isValid())
        {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

//EGRESS 用于进行数据包转出时的处理

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

//计算首部校验和
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        //调用 v1model.p4 库的函数自动计算首部校验和
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        //发送包头
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
