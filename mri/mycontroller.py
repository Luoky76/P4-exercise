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

#port topology
#s1
S1_TO_H1 = 2
S1_TO_H11 = 1
S1_TO_S2 = 3
S1_TO_S3 = 4
#s2
S2_TO_H2 = 2
S2_TO_H22 = 1
S2_TO_S1 = 3
S2_TO_S3 = 4
#s3
S3_TO_H3 = 1
S3_TO_S1 = 2
S3_TO_S2 = 3

def writeIpv4Rules(p4info_helper, sw, dst_eth_addr, dst_ip_addr, ip_mask, port_id):
    """
    write rules to table ipv4_lpm
    :param p4info_helper: the P4Info helper
    :param sw: the witch connection
    :param dst_eth_addr: the destination IP to match in the ingress rule
    :param dst_ip_addr: the destination Ethernet address to write in the
                        egress rule
    :param port_id: the egress port
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name = "MyIngress.ipv4_lpm",
        match_fields = {
            "hdr.ipv4.dstAddr": (dst_ip_addr, ip_mask)
        },
        action_name = "MyIngress.ipv4_forward",
        action_params = {
            "dstAddr": dst_eth_addr,
            "port": port_id
        }
    )
    sw.WriteTableEntry(table_entry)
    print("Installed rule on %s" % sw.name)

def writeSwtraceRules(p4info_helper, sw, swid):
    """
    :param p4info_helper: the P4Info helper
    :param sw: the witch connection
    :param swid: the index of sw
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name = "MyEgress.swtrace",
        default_action = True,
        action_name = "MyEgress.add_swtrace",
        action_params = {
            "swid": swid
        }
    )
    sw.WriteTableEntry(table_entry)
    print("Assign the index:",swid,"to",sw.name)

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
            #??????????????????????????????
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print('table name: %s' % table_name)
            #???????????????????????????
            print('match field:')
            for m in entry.match:
                print('    ', end='');
                print(p4info_helper.get_match_field_name(table_name, m.field_id), end=' ')
                print('%r' % (p4info_helper.get_match_field_value(m),))
            #???????????????????????????
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print('action name: %s' % action_name)
            #???????????????????????????
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
        # Also, dump(??????) all P4Runtime messages sent to switch to given txt files.
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

        #install the rules of table ipv4_lpm
        #s1
        print("install rules on s1...")
        writeIpv4Rules(p4info_helper, sw=s1, dst_eth_addr="08:00:00:00:01:01",
                         dst_ip_addr="10.0.1.1", ip_mask=32, port_id=S1_TO_H1)
        writeIpv4Rules(p4info_helper, sw=s1, dst_eth_addr="08:00:00:00:01:11",
                         dst_ip_addr="10.0.1.11", ip_mask=32, port_id=S1_TO_H11)
        writeIpv4Rules(p4info_helper, sw=s1, dst_eth_addr="08:00:00:00:02:00",
                         dst_ip_addr="10.0.2.0", ip_mask=24, port_id=S1_TO_S2)
        writeIpv4Rules(p4info_helper, sw=s1, dst_eth_addr="08:00:00:00:03:00",
                         dst_ip_addr="10.0.3.0", ip_mask=24, port_id=S1_TO_S3)
        writeSwtraceRules(p4info_helper, sw=s1, swid=1)
        #s2
        print("install rules on s2...")
        writeIpv4Rules(p4info_helper, sw=s2, dst_eth_addr="08:00:00:00:02:02",
                         dst_ip_addr="10.0.2.2", ip_mask=32, port_id=S2_TO_H2)
        writeIpv4Rules(p4info_helper, sw=s2, dst_eth_addr="08:00:00:00:02:22",
                         dst_ip_addr="10.0.2.22", ip_mask=32, port_id=S2_TO_H22)
        writeIpv4Rules(p4info_helper, sw=s2, dst_eth_addr="08:00:00:00:01:00",
                         dst_ip_addr="10.0.1.0", ip_mask=24, port_id=S2_TO_S1)
        writeIpv4Rules(p4info_helper, sw=s2, dst_eth_addr="08:00:00:00:03:00",
                         dst_ip_addr="10.0.3.0", ip_mask=24, port_id=S2_TO_S3)
        writeSwtraceRules(p4info_helper, sw=s2, swid=2)
        #s3
        print("install rules on s3...")
        writeIpv4Rules(p4info_helper, sw=s3, dst_eth_addr="08:00:00:00:03:03",
                         dst_ip_addr="10.0.3.3", ip_mask=32, port_id=S3_TO_H3)
        writeIpv4Rules(p4info_helper, sw=s3, dst_eth_addr="08:00:00:00:01:00",
                         dst_ip_addr="10.0.1.0", ip_mask=24, port_id=S3_TO_S1)
        writeIpv4Rules(p4info_helper, sw=s3, dst_eth_addr="08:00:00:00:02:00",
                         dst_ip_addr="10.0.2.0", ip_mask=24, port_id=S3_TO_S2)
        writeSwtraceRules(p4info_helper, sw=s3, swid=3)

        readTableRules(p4info_helper, s1)
        readTableRules(p4info_helper, s2)
        readTableRules(p4info_helper, s3)

    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    #??????????????????
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    #?????????????????????????????????????????????????????????
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/mri.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/mri.json')
    #?????????????????????
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
