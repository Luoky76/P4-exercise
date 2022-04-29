#!/usr/bin/env python3
import argparse
import grpc
import os
import sys
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

#port topology (triangle)
S_TO_H = 1
#s1
S1_TO_S2 = 2
S1_TO_S3 = 3
S1_1_MAC = "00:00:00:01:01:00"
S1_2_MAC = "00:00:00:01:02:00"
S1_3_MAC = "00:00:00:01:03:00"
#s2
S2_TO_S1 = 2
S2_TO_S3 = 3
S2_1_MAC = "00:00:00:02:01:00"
S2_2_MAC = "00:00:00:02:02:00"
S2_3_MAC = "00:00:00:02:03:00"
#s3
S3_TO_S1 = 2
S3_TO_S2 = 3
S3_1_MAC = "00:00:00:03:01:00"
S3_2_MAC = "00:00:00:03:02:00"
S3_3_MAC = "00:00:00:03:03:00"
#H
H1_MAC = "08:00:00:00:01:01"
H2_MAC = "08:00:00:00:02:02"
H3_MAC = "08:00:00:00:03:03"

def writeEcmp_groupRules(p4info_helper, sw, dst_ip_addr, ip_mask, ecmp_base, ecmp_count):
    """
    write rules to table ecmp_group
    :param p4info_helper: the P4Info helper
    :param sw: the witch connection
    :param dst_ip_addr: the virtual or real destination ip address
    :param ip_mask: the mask of ip address
    :param ecmp_base: the base index of meta.ecmp_select which decides egress port
    :param ecmp_count: the number of choices of next hop
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name = "MyIngress.ecmp_group",
        match_fields = {
            "hdr.ipv4.dstAddr": (dst_ip_addr, ip_mask)
        },
        action_name = "MyIngress.set_ecmp_select",
        action_params = {
            "ecmp_base": ecmp_base,
            "ecmp_count": ecmp_count
        })
    sw.WriteTableEntry(table_entry)

    table_entry = p4info_helper.buildTableEntry(
        table_name = "MyIngress.ecmp_group",
        default_action = True,
        action_name = "MyIngress.drop",
        action_params = {
        })
    sw.WriteTableEntry(table_entry)

    print("Installed MyIngress.ecmp_group rule on %s" % sw.name)

def writeEcmp_nhopRules(p4info_helper, sw, ecmp_select, nhop_dmac, nhop_ipv4, port_id):
    """
    write rules to table ecmp_nhop
    :param p4info_helper: the P4Info helper
    :param sw: the witch connection
    :param ecmp_select: exactly match with meta.ecmp_select. use it to decide next hop
    :param nhop_dmac: destination address of ethernet
    :param nhop_ipv4: destination address of ipv4
    :param port_id: index of egress port
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name = "MyIngress.ecmp_nhop",
        match_fields = {
            "meta.ecmp_select": ecmp_select
        },
        action_name = "MyIngress.set_nhop",
        action_params = {
            "nhop_dmac": nhop_dmac,
            "nhop_ipv4": nhop_ipv4,
            "port": port_id
        })
    sw.WriteTableEntry(table_entry)

    table_entry = p4info_helper.buildTableEntry(
        table_name = "MyIngress.ecmp_nhop",
        default_action = True,
        action_name = "MyIngress.drop",
        action_params = {
        })
    sw.WriteTableEntry(table_entry)

    print("Installed MyIngress.ecmp_nhop rule on %s" % sw.name)

def writeSend_frameRule(p4info_helper, sw, egress_port, smac):
    """
    write rules to table send_frame
    :param p4info_helper: the P4Info helper
    :param sw: the witch connection
    :param egress_port: the index of port of sw
    :param smac: the ethernet address of egress_port
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name = "MyEgress.send_frame",
        match_fields = {
            "standard_metadata.egress_port": egress_port
        },
        action_name = "MyEgress.rewrite_mac",
        action_params = {
            "smac": smac
        })
    sw.WriteTableEntry(table_entry)

    print("Installed MyEgress.send_frame tule on %s" % sw.name, "smac =", smac)


def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print('\n----- Reading tables rules for %s -----' % sw.name)
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            # TODO For extra credit, you can use the p4info_helper to translate
            #      the IDs in the entry to names
            #获取入口流表名并打印
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print('table name: %s' % table_name)
            #获取匹配字段并打印
            print('match field:')
            for m in entry.match:
                print('    ', end='');
                print(p4info_helper.get_match_field_name(table_name, m.field_id), end=' ')
                print('%r' % (p4info_helper.get_match_field_value(m),))
            #打印流表中的行为名
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print('action name: %s' % action_name)
            #打印行为的传入参数
            print('action params:')
            for p in action.params:
                print('    ', end='');
                print(p4info_helper.get_action_param_name(action_name, p.param_id), end='')
                print(': %r' % p.value)
            print()


def printCounter(p4info_helper, sw, counter_name, index):
    """
    Reads the specified counter at the specified index from the switch. In our
    program, the index is the tunnel ID. If the index is 0, it will return all
    values from the counter.

    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param counter_name: the name of the counter from the P4 program
    :param index: the counter index (in our case, the tunnel ID)
    """
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            print("%s %s %d: %d packets (%d bytes)" % (
                sw.name, counter_name, index,
                counter.data.packet_count, counter.data.byte_count
            ))

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump(导出) all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s1")
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s2")
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s3")

        #install the rules of tables
        #s1
        print("install rules on s1...")
        writeEcmp_groupRules(p4info_helper, sw=s1, dst_ip_addr="10.0.0.1", ip_mask=32, ecmp_base=2, ecmp_count=2)
        writeEcmp_groupRules(p4info_helper, sw=s1, dst_ip_addr="10.0.1.1", ip_mask=32, ecmp_base=1, ecmp_count=1)
        writeEcmp_groupRules(p4info_helper, sw=s1, dst_ip_addr="10.0.2.2", ip_mask=32, ecmp_base=2, ecmp_count=1)
        writeEcmp_groupRules(p4info_helper, sw=s1, dst_ip_addr="10.0.3.3", ip_mask=32, ecmp_base=3, ecmp_count=1)
        writeEcmp_nhopRules(p4info_helper, sw=s1, ecmp_select=1, nhop_dmac=H1_MAC, nhop_ipv4="10.0.1.1", port_id=S_TO_H)
        writeEcmp_nhopRules(p4info_helper, sw=s1, ecmp_select=2, nhop_dmac=S2_2_MAC, nhop_ipv4="10.0.2.2", port_id=S1_TO_S2)
        writeEcmp_nhopRules(p4info_helper, sw=s1, ecmp_select=3, nhop_dmac=S3_2_MAC, nhop_ipv4="10.0.3.3", port_id=S1_TO_S3)
        writeSend_frameRule(p4info_helper, sw=s1, egress_port=1, smac=S1_1_MAC)
        writeSend_frameRule(p4info_helper, sw=s1, egress_port=2, smac=S1_2_MAC)
        writeSend_frameRule(p4info_helper, sw=s1, egress_port=3, smac=S1_3_MAC)

        #s2
        print("install rules on s2...")
        writeEcmp_groupRules(p4info_helper, sw=s2, dst_ip_addr="10.0.1.1", ip_mask=32, ecmp_base=1, ecmp_count=1)
        writeEcmp_groupRules(p4info_helper, sw=s2, dst_ip_addr="10.0.2.2", ip_mask=32, ecmp_base=2, ecmp_count=1)
        writeEcmp_groupRules(p4info_helper, sw=s2, dst_ip_addr="10.0.3.3", ip_mask=32, ecmp_base=3, ecmp_count=1)
        writeEcmp_nhopRules(p4info_helper, sw=s2, ecmp_select=1, nhop_dmac=S1_2_MAC, nhop_ipv4="10.0.1.1", port_id=S2_TO_S1)
        writeEcmp_nhopRules(p4info_helper, sw=s2, ecmp_select=2, nhop_dmac=H2_MAC, nhop_ipv4="10.0.2.2", port_id=S_TO_H)
        writeEcmp_nhopRules(p4info_helper, sw=s2, ecmp_select=3, nhop_dmac=S3_3_MAC, nhop_ipv4="10.0.3.3", port_id=S2_TO_S3)
        writeSend_frameRule(p4info_helper, sw=s2, egress_port=1, smac=S2_1_MAC)
        writeSend_frameRule(p4info_helper, sw=s2, egress_port=2, smac=S2_2_MAC)
        writeSend_frameRule(p4info_helper, sw=s2, egress_port=3, smac=S2_3_MAC)

        #s3
        print("install rules on s3...")
        writeEcmp_groupRules(p4info_helper, sw=s3, dst_ip_addr="10.0.1.1", ip_mask=32, ecmp_base=1, ecmp_count=1)
        writeEcmp_groupRules(p4info_helper, sw=s3, dst_ip_addr="10.0.2.2", ip_mask=32, ecmp_base=2, ecmp_count=1)
        writeEcmp_groupRules(p4info_helper, sw=s3, dst_ip_addr="10.0.3.3", ip_mask=32, ecmp_base=3, ecmp_count=1)
        writeEcmp_nhopRules(p4info_helper, sw=s3, ecmp_select=1, nhop_dmac=S1_3_MAC, nhop_ipv4="10.0.1.1", port_id=S3_TO_S1)
        writeEcmp_nhopRules(p4info_helper, sw=s3, ecmp_select=2, nhop_dmac=S2_3_MAC, nhop_ipv4="10.0.2.2", port_id=S3_TO_S2)
        writeEcmp_nhopRules(p4info_helper, sw=s3, ecmp_select=3, nhop_dmac=H3_MAC, nhop_ipv4="10.0.3.3", port_id=S_TO_H)
        writeSend_frameRule(p4info_helper, sw=s3, egress_port=1, smac=S3_1_MAC)
        writeSend_frameRule(p4info_helper, sw=s3, egress_port=2, smac=S3_2_MAC)
        writeSend_frameRule(p4info_helper, sw=s3, egress_port=3, smac=S3_3_MAC)

        readTableRules(p4info_helper, s1)
        readTableRules(p4info_helper, s2)
        readTableRules(p4info_helper, s3)

    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    #创建解析对象
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    #向解析对象中添加关注的命令行参数或选项
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/load_balance.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/load_balance.json')
    #解析命令行参数
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
