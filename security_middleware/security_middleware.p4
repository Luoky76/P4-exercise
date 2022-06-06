/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_IPV6 = 0x86DD;
const bit<16> TYPE_ARP = 0x0806;
const bit<8> IP_TYPE_TCP = 0x06;
const bit<8> IP_TYPE_UDP = 0x11;

#define MIN_GAP_TIME 30000000
#define MAX_HOSTS 4096
#define MAX_PACKET_CNT 2
#define MAX_PACKET_BYTE 500

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
    bit<8>    protocol;	//协议 UDP=17 TCP=6
    bit<16>   hdrChecksum;	//首部校验和
    ip4Addr_t srcAddr;	//源ip
    ip4Addr_t dstAddr;	//目的ip
}

//ipv6帧头部
header ipv6_t {
    bit<4>    version;	//ip协议号
    bit<8>    trafficClass;	//通信分类
    bit<20>   flowLabel;	//流标签
    bit<16>   payLoadLen;	//有效载荷长度
    bit<8>    nextHdr;	//下一个头部 UDP=17 TCP=6
    bit<8>    hopLimit;	//跳数限制
    bit<128>  srcAddr;	//源ip
    bit<128>  dstAddr;	//目的ip
}

//tcp帧头部
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

//udp帧头部
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> pkt_length;
    bit<16> checksum;
}

//元数据 用于携带数据和配置信息
struct metadata {
    bit<1> in_ip_white;
    bit<1> in_mac_white;
    bit<1> in_black;
}

//包头部
struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    ipv6_t       ipv6;
    tcp_t        tcp;
    udp_t        udp;
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
        transition parse_ethernet;
    }
    
    //解析以太网帧
    state parse_ethernet {
        packet.extract(hdr.ethernet);	//提取包中的以太网帧头
        //根据以太网帧的 etherType 字段决定 transition 的下个状态
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;	//0x0800为ipv4
            TYPE_IPV6: parse_ipv6;	//0x86DD为ipv6
            default: accept;
        }
    }
    
    //解析ipv4
    state parse_ipv4 {
        packet.extract(hdr.ipv4);	//继续提取ipv4头
        transition select(hdr.ipv4.protocol) {
            IP_TYPE_TCP: parse_tcp;
            IP_TYPE_UDP: parse_udp;
            default: accept;
        }
    }
    
    //解析ipv6
    state parse_ipv6 {
        packet.extract(hdr.ipv6);	//继续提取ipv6头
        transition select(hdr.ipv6.nextHdr) {
            IP_TYPE_TCP: parse_tcp;
            IP_TYPE_UDP: parse_udp;
            default: accept;
        }
    }
    
    //解析tcp
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    
    //解析udp
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
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
                  
    //声明寄存器用于记录各个主机发送的包数和字节数
    register<bit<32>>(MAX_HOSTS) packet_cnt_reg;
    register<bit<32>>(MAX_HOSTS) byte_cnt_reg;
    register<bit<48>>(MAX_HOSTS) last_time_reg;

    //只允许在白名单并且不在黑名单的包通过
    //声明寄存器用于记录黑名单，每一位代表一台主机，1为禁止，0为允许
    register<bit<1>>(MAX_HOSTS) ban_list_reg;

    //声明便利存储黑名单寄存器对应位置的值
    bit<1> ban;
    
    //声明变量用于存储当前报文的源主机对应的寄存器位置
    bit<32> reg_pos; 
    bit<32> reg_packet_cnt_val;
    bit<32> reg_byte_cnt_val;
    bit<48> reg_last_time_val;

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

    action ipv6_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit-1;//这个类似ipv4中ttl，为0时就超时
    }
      
    table ipv6_lpm {
        key = {
            hdr.ipv6.dstAddr: lpm;
        }
          
        actions = {
            ipv6_forward;//转发
            drop;//丢弃
            NoAction;//空动作
        }
        size = 1024;//流表项容量
        default_action = drop();//table miss 则丢弃
    }  

    action set_ip_white(){
        meta.in_ip_white=1;
    }

    action set_mac_white(){
        meta.in_mac_white=1;
    }

    table ipv4_white_exact{
        key = {
            hdr.ipv4.srcAddr: ternary;
            hdr.ethernet.srcAddr: ternary;
        }
        
        actions={
            set_ip_white;
            set_mac_white;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }


    //更新寄存器的值
    action update_register() {
        //包数+1
        packet_cnt_reg.read(reg_packet_cnt_val, reg_pos);
        packet_cnt_reg.write(reg_pos, reg_packet_cnt_val + 1);
        
        //从标准元数据中读取包长并更新主机发送的字节数
        byte_cnt_reg.read(reg_byte_cnt_val, reg_pos);
        byte_cnt_reg.write(reg_pos, reg_byte_cnt_val + standard_metadata.packet_length);

        //读取上次进包时间
        last_time_reg.read(reg_last_time_val,reg_pos);
    }

    action set_black(){
        ban_list_reg.write(reg_pos,1);
        meta.in_black=1;
    }

    action reset_black(){
        last_time_reg.write(reg_pos,standard_metadata.ingress_global_timestamp);
        ban_list_reg.write(reg_pos,0);
        packet_cnt_reg.write(reg_pos,0);
        byte_cnt_reg.write(reg_pos,0);
    }

    //通过哈希源ip地址和源mac地址来得到主机的一个标识号
    action compute_ipv4_hashes(ip4Addr_t ipAddr, macAddr_t macAddr) {
       //利用哈希函数crc32得到寄存器位置
       //返回值在[0,4095]之间
       hash(reg_pos, HashAlgorithm.crc32, (bit<32>)0, {ipAddr,
                                                       macAddr},
                                                       (bit<32>)MAX_HOSTS);
       //FIXME 当哈希值发生冲突时将会出错
    }
    
    action compute_ipv6_hashes(ip6Addr_t ipAddr, macAddr_t macAddr) {
       //利用哈希函数crc32得到寄存器位置
       //返回值在[0,4095]之间
       hash(reg_pos, HashAlgorithm.crc32, (bit<32>)0, {ipAddr,
                                                       macAddr},
                                                       (bit<32>)MAX_HOSTS);
    }
    
    action check_ban_list() {
        ban_list_reg.read(ban, reg_pos);
    }

    apply {
        //如果 ipv4 有效，则执行 ipv4 的匹配 table
        if (hdr.ipv4.isValid())
        {
            compute_ipv4_hashes(hdr.ipv4.srcAddr, hdr.ethernet.srcAddr);
            update_register();

            if(standard_metadata.ingress_global_timestamp - reg_last_time_val < MIN_GAP_TIME){
                if(reg_byte_cnt_val>=MAX_PACKET_BYTE || reg_packet_cnt_val>=MAX_PACKET_CNT){
                    set_black();
                }
            }else{
                reset_black();
            }

            check_ban_list();
            ipv4_white_exact.apply();
            if (ban == 1 || meta.in_ip_white == 0 || meta.in_mac_white == 0) {
                drop();
            }else{
                ipv4_lpm.apply();
            }
        }

        //如果 ipv6 有效，则执行 ipv6 的匹配 table
        if (hdr.ipv6.isValid())
        {
            compute_ipv6_hashes(hdr.ipv6.srcAddr, hdr.ethernet.srcAddr);
            update_register();

            if(standard_metadata.ingress_global_timestamp - reg_last_time_val < MIN_GAP_TIME){
                if(reg_byte_cnt_val>=MAX_PACKET_BYTE || reg_packet_cnt_val<=MAX_PACKET_CNT){
                    set_black();
                }
            }else{
                reset_black();
            }

            check_ban_list();
            if (ban == 1) drop();
            ipv6_lpm.apply();
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
        //调用 v1model.p4 库的函数自动计算ipv4首部校验和
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
        packet.emit(hdr.ipv6);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
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
