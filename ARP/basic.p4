/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_IPV6 = 0x86DD;
const bit<16> TYPE_ARP = 0x0806;
const bit<8> IPPROTO_ICMP = 0x01;	//ipv4报文中的协议类型为0x01时表示ICMP报文

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

//ARP常量
const bit<16> ARP_HTYPE_ETHERNET = 0x0001;	//硬件类型-以太网
const bit<16> ARP_PTYPE_IPV4 = 0x0800;	//上层协议类型-ipv4
const bit<8> ARP_HLEN_ETHERNET = 6;	//MAC地址长度
const bit<8> ARP_PLEN_IPV4 = 4;	//IP地址协议长度
const bit<16> ARP_OPER_REQUEST = 1;	//操作类型-请求
const bit<16> ARP_OPER_REPLY = 2;	//操作类型-应答


//ARP报头
header arp_t {
    bit<16> htype;	//硬件类型
    bit<16> ptype;	//上层协议类型
    bit<8> hlen;	//MAC地址长度
    bit<8> plen;	//IP地址长度
    bit<16> oper;	//操作类型
}

//ARP内容
header arp_ipv4_t {
    macAddr_t srcMac;	//源MAC地址
    ip4Addr_t srcIP;	//源IP地址
    macAddr_t dstMac;	//目的MAC地址
    ip4Addr_t dstIP;	//目的IP地址
}

//ICMP常量
const bit<8> ICMP_ECHO_REQUEST = 8;	//回显请求
const bit<8> ICMP_ECHO_REPLY = 0;	//回显应答

//ICMP报头
header icmp_t {
    bit<8>  type;	//类型
    bit<8>  code;	//代码
    bit<16> checksum;	//校验和
}

//元数据 用于携带数据和配置信息
struct metadata {
    ipv4_addr_t dstIP;	//目的IP
    mac_addr_t  dstMac;	//目的MAC
    mac_addr_t  srcMac;	//源MAC
    port_id_t   egress_port;	//输出端口
    mac_addr_t  myMac;	//本地MAC
}

//包头部
struct headers {
    ethernet_t   ethernet;
    arp_t        arp;
    arp_ipv4_t   arp_ipv4;
    ipv4_t       ipv4;
    icmp_t       icmp;
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
    
    //解析以太网帧
    state ethernet_state {
        packet.extract(hdr.ethernet);	//提取包中的以太网帧头
        //根据以太网帧的 etherType 字段决定 transition 的下个状态
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: ipv4_state;	//0x800为ipv4
            TYPE_ARP: arp_state;	//0x806为ARP
            default: accept;
        }
    }
    
    //解析ARP帧
    state arp_state {
        packet.extract(hdr.arp);
        transition select(hdr.arp.htype,hdr.arp.ptype,hdr.arp.hlen,hdr.arp.plen) {
            (ARP_HTYPE_ETHERNET,ARP_PTYPE_IPV4,ARP_HLEN_ETHERNET,ARP_PLEN_IPV4): arp_ipv4_state;
            default : accept;
        }
    }
    
    //解析ARP_IPV4内容
    state arp_ipv4_state {
        packet.extract(hdr.arp_ipv4);
        meta.dstIP = hdr.arp_ipv4.dstIP;	//元数据记录下ARP报文的目的IP
        transition accept;
    }
    
    //解析ipv4
    state ipv4_state {
        packet.extract(hdr.ipv4);	//提取ipv4头
        meta.dstIP = hdr.ipv4.dstAddr;	//元数据记录下IP报文的目的IP
        transition select(hdr.ipv4.protocol) {
            IPPROTO_ICMP: parse_icmp;	//对ICMP报文进行进一步解析
            default: accept;
        }
    }
    
    //解析ICMP报文
    state icmp_state {
        packet.extract(hdr.icmp);
        transition: accept;
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


/*TODO 部分行为尚未完成*/

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
    
    //针对ARP和ICMP的表项
    table forward {
        key = {
            hdr.arp.isValid(): exact;
            hdr.arp.oper: exact;
            hdr.arp_ipv4.isValid() : exact;
            hdr.ipv4.isValid() : exact;
            hdr.icmp.isValid() : exact;
            hdr.icmp.type : ternary;
        }
        actions = {
            ipv4_forward;
            send_arp_reply;
            send_icmp_reply;
            drop;
        }
        const default_action = drop();
        const entries = {
            //ARP请求
            (true,ARP_OPER_REQUEST,true,false,false,_): send_arp_reply();
            //普通ipv4报文
            (false,_,false,true,false,_): ipv4_forward();
            //ICMP请求
            (false,_,false,true,true,ICMP_ECHO_REQUEST): send_icmp_reply();
        }
    }

    apply {
        //如果 ipv4 有效，则执行 ipv4 的匹配 table
        if (hdr.ipv4.isValid())
        {
            ipv4_lpm.apply();
        }
        //无条件进入forward表
        forward.apply();
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
        /* ARP Case */
        packet.emit(hdr.arp);
        packet.emit(hdr.arp_ipv4);
        /* IPv4 case */
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
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
