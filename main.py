from tkinter import *
from scapy.all import *

root = Tk()
root.geometry("700x350+430+250")
wait_var = StringVar()

# ether tcp
ether_tcp = StringVar()

# ether udp
ether_udp = StringVar()

# ether options
def ether_options():
    global text_mac_src, text_mac_dst
    # src mac
    label_mac_src = Label(root, text="SRC MAC", fg="white", bg="black")
    label_mac_src.place(x=5, y=85)
    text_mac_src = Text(root, height=1, width=17, fg="white", bg="black", insertbackground="white")
    text_mac_src.place(x=70, y=85)

    # dst mac
    label_mac_dst = Label(root, text="DST MAC", fg="white", bg="black")
    label_mac_dst.place(x=5, y=115)
    text_mac_dst = Text(root, height=1, width=17, fg="white", bg="black", insertbackground="white")
    text_mac_dst.place(x=70, y=115)

    # type
    label_type = Label(root, text="TYPE", fg="white", bg="black")
    label_type.place(x=220, y=85)
    text_type = Text(root, height=1, width=17, fg="white", bg="black", insertbackground="white")
    text_type.place(x=255, y=85)
# send packet
def send_packet():
    if ip_p == True:
        if wait_var.get() == "wait":
            ans, unans = sr(IP(src=str(text_src.get("1.0", "end-1c")), dst=str(text_dst.get("1.0", "end-1c")), ihl=int(text_hl.get("1.0", "end-1c")), tos=int(text_tos.get("1.0", "end-1c")), len=int(text_len.get("1.0", "end-1c")), id=int(text_id.get("1.0", "end-1c")), flags=int(text_flag.get("1.0", "end-1c")), frag=int(text_frag.get("1.0", "end-1c")), ttl=int(text_ttl.get("1.0", "end-1c")), proto=int(text_proto.get("1.0", "end-1c")), chksum=int(text_checksum.get("1.0", "end-1c")), options=int(text_option.get("1.0", "end-1c"))))
            for p in ans:
                print(p[0])
                print(p[1])
            for p in unans:
                print(p[0])
        else:
            scapy.sendrecv.send(IP(src=str(text_src.get("1.0", "end-1c")), dst=str(text_dst.get("1.0", "end-1c")), ihl=int(text_hl.get("1.0", "end-1c")), tos=int(text_tos.get("1.0", "end-1c")), len=int(text_len.get("1.0", "end-1c")), id=int(text_id.get("1.0", "end-1c")), flags=int(text_flag.get("1.0", "end-1c")), frag=int(text_frag.get("1.0", "end-1c")), ttl=int(text_ttl.get("1.0", "end-1c")), proto=int(text_proto.get("1.0", "end-1c")), chksum=int(text_checksum.get("1.0", "end-1c")), options=int(text_option.get("1.0", "end-1c"))), count=int(text_count.get("1.0", "end-1c")))
    elif tcp_p == True:
        if wait_var.get() == "wait":
            if ether_tcp.get() == "ether_udp":
                ans, unans = sr(Ether(src=str(text_mac_src.get("1.0", "end-1c")), dst=str(text_mac_dst.get("1.0", "end-1c")))/IP(src=str(text_src.get("1.0", "end-1c")), dst=str(text_dst.get("1.0", "end-1c")), ihl=int(text_hl.get("1.0", "end-1c")), tos=int(text_tos.get("1.0", "end-1c")), len=int(text_len.get("1.0", "end-1c")), id=int(text_id.get("1.0", "end-1c")), flags=int(text_flag.get("1.0", "end-1c")), frag=int(text_frag.get("1.0", "end-1c")), ttl=int(text_ttl.get("1.0", "end-1c")), proto=int(text_proto.get("1.0", "end-1c")), chksum=int(text_checksum.get("1.0", "end-1c")), options=int(text_option.get("1.0", "end-1c")))/TCP(sport=int(text_sprt.get("1.0", "end-1c")), dport=int(text_dprt.get("1.0", "end-1c")), text_seq=int(text_seq.get("1.0", "end-1c")), ack=int(text_ack.get("1.0", "end-1c")), dataofs=int(text_dataofs.get("1.0", "end-1c")), reserved=int(text_reserved.get("1.0", "end-1c")), flags=int(text_tcp_flags.get("1.0", "end-1c")), window=int(text_window.get("1.0", "end-1c")), chksum=int(text_tcp_checksum.get("1.0", "end-1c")), urgptr=int(text_urgptr.get("1.0", "end-1c")), options=int(text_tcp_options.get("1.0", "end-1c"))))
            elif ether_tcp.get() == "":
                ans, unans = sr(IP(src=str(text_src.get("1.0", "end-1c")), dst=str(text_dst.get("1.0", "end-1c")), ihl=int(text_hl.get("1.0", "end-1c")), tos=int(text_tos.get("1.0", "end-1c")), len=int(text_len.get("1.0", "end-1c")), id=int(text_id.get("1.0", "end-1c")), flags=int(text_flag.get("1.0", "end-1c")), frag=int(text_frag.get("1.0", "end-1c")), ttl=int(text_ttl.get("1.0", "end-1c")), proto=int(text_proto.get("1.0", "end-1c")), chksum=int(text_checksum.get("1.0", "end-1c")), options=int(text_option.get("1.0", "end-1c")))/TCP(sport=int(text_sprt.get("1.0", "end-1c")), dport=int(text_dprt.get("1.0", "end-1c")), text_seq=int(text_seq.get("1.0", "end-1c")), ack=int(text_ack.get("1.0", "end-1c")), dataofs=int(text_dataofs.get("1.0", "end-1c")), reserved=int(text_reserved.get("1.0", "end-1c")), flags=int(text_tcp_flags.get("1.0", "end-1c")), window=int(text_window.get("1.0", "end-1c")), chksum=int(text_tcp_checksum.get("1.0", "end-1c")), urgptr=int(text_urgptr.get("1.0", "end-1c")), options=int(text_tcp_options.get("1.0", "end-1c"))))
            for p in ans:
                print(p[0])
                print(p[1])
            for p in unans:
                print(p[0])
        else:
            if ether_tcp.get() == "ether_tcp":
                scapy.sendrecv.sendp(Ether(src=str(text_mac_src.get("1.0", "end-1c")), dst=str(text_mac_dst.get("1.0", "end-1c")))/IP(src=str(text_src.get("1.0", "end-1c")), dst=str(text_dst.get("1.0", "end-1c")), ihl=int(text_hl.get("1.0", "end-1c")), tos=int(text_tos.get("1.0", "end-1c")), len=int(text_len.get("1.0", "end-1c")), id=int(text_id.get("1.0", "end-1c")), flags=int(text_flag.get("1.0", "end-1c")), frag=int(text_frag.get("1.0", "end-1c")), ttl=int(text_ttl.get("1.0", "end-1c")), proto=int(text_proto.get("1.0", "end-1c")), chksum=int(text_checksum.get("1.0", "end-1c")), options=int(text_option.get("1.0", "end-1c")))/TCP(sport=int(text_sprt.get("1.0", "end-1c")), dport=int(text_dprt.get("1.0", "end-1c")), text_seq=int(text_seq.get("1.0", "end-1c")), ack=int(text_ack.get("1.0", "end-1c")), dataofs=int(text_dataofs.get("1.0", "end-1c")), reserved=int(text_reserved.get("1.0", "end-1c")), flags=int(text_tcp_flags.get("1.0", "end-1c")), window=int(text_window.get("1.0", "end-1c")), chksum=int(text_tcp_checksum.get("1.0", "end-1c")), urgptr=int(text_urgptr.get("1.0", "end-1c")), options=int(text_tcp_options.get("1.0", "end-1c"))), count=int(text_count.get("1.0", "end-1c")))
            elif ether_tcp.get() == "":
                scapy.sendrecv.send(IP(src=str(text_src.get("1.0", "end-1c")), dst=str(text_dst.get("1.0", "end-1c")), ihl=int(text_hl.get("1.0", "end-1c")), tos=int(text_tos.get("1.0", "end-1c")), len=int(text_len.get("1.0", "end-1c")), id=int(text_id.get("1.0", "end-1c")), flags=int(text_flag.get("1.0", "end-1c")), frag=int(text_frag.get("1.0", "end-1c")), ttl=int(text_ttl.get("1.0", "end-1c")), proto=int(text_proto.get("1.0", "end-1c")), chksum=int(text_checksum.get("1.0", "end-1c")), options=int(text_option.get("1.0", "end-1c")))/TCP(sport=int(text_sprt.get("1.0", "end-1c")), dport=int(text_dprt.get("1.0", "end-1c")), text_seq=int(text_seq.get("1.0", "end-1c")), ack=int(text_ack.get("1.0", "end-1c")), dataofs=int(text_dataofs.get("1.0", "end-1c")), reserved=int(text_reserved.get("1.0", "end-1c")), flags=int(text_tcp_flags.get("1.0", "end-1c")), window=int(text_window.get("1.0", "end-1c")), chksum=int(text_tcp_checksum.get("1.0", "end-1c")), urgptr=int(text_urgptr.get("1.0", "end-1c")), options=int(text_tcp_options.get("1.0", "end-1c"))), count=int(text_count.get("1.0", "end-1c")))
    elif udp_p == True:
        if wait_var.get() == "wait":
            if ether_udp.get() == "ether_udp":
                ans, unans = sr(Ether(src=str(text_mac_src.get("1.0", "end-1c")), dst=str(text_mac_dst.get("1.0", "end-1c")))/IP(src=str(text_src.get("1.0", "end-1c")), dst=str(text_dst.get("1.0", "end-1c")), ihl=int(text_hl.get("1.0", "end-1c")), tos=int(text_tos.get("1.0", "end-1c")), len=int(text_len.get("1.0", "end-1c")), id=int(text_id.get("1.0", "end-1c")), flags=int(text_flag.get("1.0", "end-1c")), frag=int(text_frag.get("1.0", "end-1c")), ttl=int(text_ttl.get("1.0", "end-1c")), proto=int(text_proto.get("1.0", "end-1c")), chksum=int(text_checksum.get("1.0", "end-1c")), options=int(text_option.get("1.0", "end-1c")))/UDP(sport=int(text_sprt.get("1.0", "end-1c")), dport=int(text_dprt.get("1.0", "end-1c")), len=int(text_udp_len.get("1.0", "end-1c")), chksum=int(text_udp_checksum.get("1.0", "end-1c"))))
            else:
                ans, unans = sr(IP(src=str(text_src.get("1.0", "end-1c")), dst=str(text_dst.get("1.0", "end-1c")), ihl=int(text_hl.get("1.0", "end-1c")), tos=int(text_tos.get("1.0", "end-1c")), len=int(text_len.get("1.0", "end-1c")), id=int(text_id.get("1.0", "end-1c")), flags=int(text_flag.get("1.0", "end-1c")), frag=int(text_frag.get("1.0", "end-1c")), ttl=int(text_ttl.get("1.0", "end-1c")), proto=int(text_proto.get("1.0", "end-1c")), chksum=int(text_checksum.get("1.0", "end-1c")), options=int(text_option.get("1.0", "end-1c")))/UDP(sport=int(text_sprt.get("1.0", "end-1c")), dport=int(text_dprt.get("1.0", "end-1c")), len=int(text_udp_len.get("1.0", "end-1c")), chksum=int(text_udp_checksum.get("1.0", "end-1c"))))
            for p in ans:
                print(p[0])
                print(p[1])
            for p in unans:
                print(p[0])
        else:
            if ether_udp.get() == "ether_udp":
                scapy.sendrecv.sendp(Ether(src=str(text_mac_src.get("1.0", "end-1c")), dst=str(text_mac_dst.get("1.0", "end-1c")))/IP(src=str(text_src.get("1.0", "end-1c")), dst=str(text_dst.get("1.0", "end-1c")), ihl=int(text_hl.get("1.0", "end-1c")), tos=int(text_tos.get("1.0", "end-1c")), len=int(text_len.get("1.0", "end-1c")), id=int(text_id.get("1.0", "end-1c")), flags=int(text_flag.get("1.0", "end-1c")), frag=int(text_frag.get("1.0", "end-1c")), ttl=int(text_ttl.get("1.0", "end-1c")), proto=int(text_proto.get("1.0", "end-1c")), chksum=int(text_checksum.get("1.0", "end-1c")), options=int(text_option.get("1.0", "end-1c")))/UDP(sport=int(text_sprt.get("1.0", "end-1c")), dport=int(text_dprt.get("1.0", "end-1c")), len=int(text_udp_len.get("1.0", "end-1c")), chksum=int(text_udp_checksum.get("1.0", "end-1c"))), count=int(text_count.get("1.0", "end-1c")))
            else:
                scapy.sendrecv.send(IP(src=str(text_src.get("1.0", "end-1c")), dst=str(text_dst.get("1.0", "end-1c")), ihl=int(text_hl.get("1.0", "end-1c")), tos=int(text_tos.get("1.0", "end-1c")), len=int(text_len.get("1.0", "end-1c")), id=int(text_id.get("1.0", "end-1c")), flags=int(text_flag.get("1.0", "end-1c")), frag=int(text_frag.get("1.0", "end-1c")), ttl=int(text_ttl.get("1.0", "end-1c")), proto=int(text_proto.get("1.0", "end-1c")), chksum=int(text_checksum.get("1.0", "end-1c")), options=int(text_option.get("1.0", "end-1c")))/UDP(sport=int(text_sprt.get("1.0", "end-1c")), dport=int(text_dprt.get("1.0", "end-1c")), len=int(text_udp_len.get("1.0", "end-1c")), chksum=int(text_udp_checksum.get("1.0", "end-1c"))), count=int(text_count.get("1.0", "end-1c")))

# infomation
def show_info():
    if tcp_p == True:
        if ether_tcp.get() == "ether_tcp":
            Ether(src=str(text_mac_src.get("1.0", "end-1c")), dst=str(text_mac_dst.get("1.0", "end-1c")))/IP(src=str(text_src.get("1.0", "end-1c")), dst=str(text_dst.get("1.0", "end-1c")), ihl=int(text_hl.get("1.0", "end-1c")), tos=int(text_tos.get("1.0", "end-1c")), len=int(text_len.get("1.0", "end-1c")), id=int(text_id.get("1.0", "end-1c")), flags=int(text_flag.get("1.0", "end-1c")), frag=int(text_frag.get("1.0", "end-1c")), ttl=int(text_ttl.get("1.0", "end-1c")), proto=int(text_proto.get("1.0", "end-1c")), chksum=int(text_checksum.get("1.0", "end-1c")), options=int(text_option.get("1.0", "end-1c")))/TCP(sport=int(text_sprt.get("1.0", "end-1c")), dport=int(text_dprt.get("1.0", "end-1c")), text_seq=int(text_seq.get("1.0", "end-1c")), ack=int(text_ack.get("1.0", "end-1c")), dataofs=int(text_dataofs.get("1.0", "end-1c")), reserved=int(text_reserved.get("1.0", "end-1c")), flags=int(text_tcp_flags.get("1.0", "end-1c")), window=int(text_window.get("1.0", "end-1c")), chksum=int(text_tcp_checksum.get("1.0", "end-1c")), urgptr=int(text_urgptr.get("1.0", "end-1c")), options=int(text_tcp_options.get("1.0", "end-1c"))).show2()
        else:
            IP(src=str(text_src.get("1.0", "end-1c")), dst=str(text_dst.get("1.0", "end-1c")), ihl=int(text_hl.get("1.0", "end-1c")), tos=int(text_tos.get("1.0", "end-1c")), len=int(text_len.get("1.0", "end-1c")), id=int(text_id.get("1.0", "end-1c")), flags=int(text_flag.get("1.0", "end-1c")), frag=int(text_frag.get("1.0", "end-1c")), ttl=int(text_ttl.get("1.0", "end-1c")), proto=int(text_proto.get("1.0", "end-1c")), chksum=int(text_checksum.get("1.0", "end-1c")), options=int(text_option.get("1.0", "end-1c")))/TCP(sport=int(text_sprt.get("1.0", "end-1c")), dport=int(text_dprt.get("1.0", "end-1c")), text_seq=int(text_seq.get("1.0", "end-1c")), ack=int(text_ack.get("1.0", "end-1c")), dataofs=int(text_dataofs.get("1.0", "end-1c")), reserved=int(text_reserved.get("1.0", "end-1c")), flags=int(text_tcp_flags.get("1.0", "end-1c")), window=int(text_window.get("1.0", "end-1c")), chksum=int(text_tcp_checksum.get("1.0", "end-1c")), urgptr=int(text_urgptr.get("1.0", "end-1c")), options=int(text_tcp_options.get("1.0", "end-1c"))).show2()    
    elif udp_p == True:
        if ether_udp.get() == "ether_udp":
            Ether(src=str(text_mac_src.get("1.0", "end-1c")), dst=str(text_mac_dst.get("1.0", "end-1c")))/IP(src=str(text_src.get("1.0", "end-1c")), dst=str(text_dst.get("1.0", "end-1c")), ihl=int(text_hl.get("1.0", "end-1c")), tos=int(text_tos.get("1.0", "end-1c")), len=int(text_len.get("1.0", "end-1c")), id=int(text_id.get("1.0", "end-1c")), flags=int(text_flag.get("1.0", "end-1c")), frag=int(text_frag.get("1.0", "end-1c")), ttl=int(text_ttl.get("1.0", "end-1c")), proto=int(text_proto.get("1.0", "end-1c")), chksum=int(text_checksum.get("1.0", "end-1c")), options=int(text_option.get("1.0", "end-1c")))/UDP(sport=int(text_sprt.get("1.0", "end-1c")), dport=int(text_dprt.get("1.0", "end-1c")), text_seq=int(text_seq.get("1.0", "end-1c")), ack=int(text_ack.get("1.0", "end-1c")), dataofs=int(text_dataofs.get("1.0", "end-1c")), reserved=int(text_reserved.get("1.0", "end-1c")), flags=int(text_tcp_flags.get("1.0", "end-1c")), window=int(text_window.get("1.0", "end-1c")), chksum=int(text_tcp_checksum.get("1.0", "end-1c")), urgptr=int(text_urgptr.get("1.0", "end-1c")), options=int(text_tcp_options.get("1.0", "end-1c"))).show2()
        else:
            IP(src=str(text_src.get("1.0", "end-1c")), dst=str(text_dst.get("1.0", "end-1c")), ihl=int(text_hl.get("1.0", "end-1c")), tos=int(text_tos.get("1.0", "end-1c")), len=int(text_len.get("1.0", "end-1c")), id=int(text_id.get("1.0", "end-1c")), flags=int(text_flag.get("1.0", "end-1c")), frag=int(text_frag.get("1.0", "end-1c")), ttl=int(text_ttl.get("1.0", "end-1c")), proto=int(text_proto.get("1.0", "end-1c")), chksum=int(text_checksum.get("1.0", "end-1c")), options=int(text_option.get("1.0", "end-1c")))/UDP(sport=int(text_sprt.get("1.0", "end-1c")), dport=int(text_dprt.get("1.0", "end-1c")), text_seq=int(text_seq.get("1.0", "end-1c")), ack=int(text_ack.get("1.0", "end-1c")), dataofs=int(text_dataofs.get("1.0", "end-1c")), reserved=int(text_reserved.get("1.0", "end-1c")), flags=int(text_tcp_flags.get("1.0", "end-1c")), window=int(text_window.get("1.0", "end-1c")), chksum=int(text_tcp_checksum.get("1.0", "end-1c")), urgptr=int(text_urgptr.get("1.0", "end-1c")), options=int(text_tcp_options.get("1.0", "end-1c"))).show2()
    elif ip_p == True:
        IP(src=str(text_src.get("1.0", "end-1c")), dst=str(text_dst.get("1.0", "end-1c")), ihl=int(text_hl.get("1.0", "end-1c")), tos=int(text_tos.get("1.0", "end-1c")), len=int(text_len.get("1.0", "end-1c")), id=int(text_id.get("1.0", "end-1c")), flags=int(text_flag.get("1.0", "end-1c")), frag=int(text_frag.get("1.0", "end-1c")), ttl=int(text_ttl.get("1.0", "end-1c")), proto=int(text_proto.get("1.0", "end-1c")), chksum=int(text_checksum.get("1.0", "end-1c")), options=int(text_option.get("1.0", "end-1c"))).show2()
# hex dump
def hex_dump():
    if tcp_p == True:
        if ether_tcp.get() == "ether_tcp":
            hexdump(Ether(src=str(text_mac_src.get("1.0", "end-1c")), dst=str(text_mac_dst.get("1.0", "end-1c")))/IP(src=str(text_src.get("1.0", "end-1c")), dst=str(text_dst.get("1.0", "end-1c")), ihl=int(text_hl.get("1.0", "end-1c")), tos=int(text_tos.get("1.0", "end-1c")), len=int(text_len.get("1.0", "end-1c")), id=int(text_id.get("1.0", "end-1c")), flags=int(text_flag.get("1.0", "end-1c")), frag=int(text_frag.get("1.0", "end-1c")), ttl=int(text_ttl.get("1.0", "end-1c")), proto=int(text_proto.get("1.0", "end-1c")), chksum=int(text_checksum.get("1.0", "end-1c")), options=int(text_option.get("1.0", "end-1c")))/TCP(sport=int(text_sprt.get("1.0", "end-1c")), dport=int(text_dprt.get("1.0", "end-1c")), text_seq=int(text_seq.get("1.0", "end-1c")), ack=int(text_ack.get("1.0", "end-1c")), dataofs=int(text_dataofs.get("1.0", "end-1c")), reserved=int(text_reserved.get("1.0", "end-1c")), flags=int(text_tcp_flags.get("1.0", "end-1c")), window=int(text_window.get("1.0", "end-1c")), chksum=int(text_tcp_checksum.get("1.0", "end-1c")), urgptr=int(text_urgptr.get("1.0", "end-1c")), options=int(text_tcp_options.get("1.0", "end-1c"))), count=int(text_count.get("1.0", "end-1c")))
        else:
            hexdump(IP(src=str(text_src.get("1.0", "end-1c")), dst=str(text_dst.get("1.0", "end-1c")), ihl=int(text_hl.get("1.0", "end-1c")), tos=int(text_tos.get("1.0", "end-1c")), len=int(text_len.get("1.0", "end-1c")), id=int(text_id.get("1.0", "end-1c")), flags=int(text_flag.get("1.0", "end-1c")), frag=int(text_frag.get("1.0", "end-1c")), ttl=int(text_ttl.get("1.0", "end-1c")), proto=int(text_proto.get("1.0", "end-1c")), chksum=int(text_checksum.get("1.0", "end-1c")), options=int(text_option.get("1.0", "end-1c")))/TCP(sport=int(text_sprt.get("1.0", "end-1c")), dport=int(text_dprt.get("1.0", "end-1c")), text_seq=int(text_seq.get("1.0", "end-1c")), ack=int(text_ack.get("1.0", "end-1c")), dataofs=int(text_dataofs.get("1.0", "end-1c")), reserved=int(text_reserved.get("1.0", "end-1c")), flags=int(text_tcp_flags.get("1.0", "end-1c")), window=int(text_window.get("1.0", "end-1c")), chksum=int(text_tcp_checksum.get("1.0", "end-1c")), urgptr=int(text_urgptr.get("1.0", "end-1c")), options=int(text_tcp_options.get("1.0", "end-1c"))), count=int(text_count.get("1.0", "end-1c")))
    elif udp_p == True:
        if ether_udp.get() == "ether_udp":
            hexdump(Ether(src=str(text_mac_src.get("1.0", "end-1c")), dst=str(text_mac_dst.get("1.0", "end-1c")))/IP(src=str(text_src.get("1.0", "end-1c")), dst=str(text_dst.get("1.0", "end-1c")), ihl=int(text_hl.get("1.0", "end-1c")), tos=int(text_tos.get("1.0", "end-1c")), len=int(text_len.get("1.0", "end-1c")), id=int(text_id.get("1.0", "end-1c")), flags=int(text_flag.get("1.0", "end-1c")), frag=int(text_frag.get("1.0", "end-1c")), ttl=int(text_ttl.get("1.0", "end-1c")), proto=int(text_proto.get("1.0", "end-1c")), chksum=int(text_checksum.get("1.0", "end-1c")), options=int(text_option.get("1.0", "end-1c")))/UDP(sport=int(text_sprt.get("1.0", "end-1c")), dport=int(text_dprt.get("1.0", "end-1c")), text_seq=int(text_seq.get("1.0", "end-1c")), ack=int(text_ack.get("1.0", "end-1c")), dataofs=int(text_dataofs.get("1.0", "end-1c")), reserved=int(text_reserved.get("1.0", "end-1c")), flags=int(text_tcp_flags.get("1.0", "end-1c")), window=int(text_window.get("1.0", "end-1c")), chksum=int(text_tcp_checksum.get("1.0", "end-1c")), urgptr=int(text_urgptr.get("1.0", "end-1c")), options=int(text_tcp_options.get("1.0", "end-1c"))), count=int(text_count.get("1.0", "end-1c")))
        else:
            hexdump(IP(src=str(text_src.get("1.0", "end-1c")), dst=str(text_dst.get("1.0", "end-1c")), ihl=int(text_hl.get("1.0", "end-1c")), tos=int(text_tos.get("1.0", "end-1c")), len=int(text_len.get("1.0", "end-1c")), id=int(text_id.get("1.0", "end-1c")), flags=int(text_flag.get("1.0", "end-1c")), frag=int(text_frag.get("1.0", "end-1c")), ttl=int(text_ttl.get("1.0", "end-1c")), proto=int(text_proto.get("1.0", "end-1c")), chksum=int(text_checksum.get("1.0", "end-1c")), options=int(text_option.get("1.0", "end-1c")))/UDP(sport=int(text_sprt.get("1.0", "end-1c")), dport=int(text_dprt.get("1.0", "end-1c")), text_seq=int(text_seq.get("1.0", "end-1c")), ack=int(text_ack.get("1.0", "end-1c")), dataofs=int(text_dataofs.get("1.0", "end-1c")), reserved=int(text_reserved.get("1.0", "end-1c")), flags=int(text_tcp_flags.get("1.0", "end-1c")), window=int(text_window.get("1.0", "end-1c")), chksum=int(text_tcp_checksum.get("1.0", "end-1c")), urgptr=int(text_urgptr.get("1.0", "end-1c")), options=int(text_tcp_options.get("1.0", "end-1c"))), count=int(text_count.get("1.0", "end-1c")))
    elif ip_p == True:
        hexdump(IP(src=str(text_src.get("1.0", "end-1c")), dst=str(text_dst.get("1.0", "end-1c")), ihl=int(text_hl.get("1.0", "end-1c")), tos=int(text_tos.get("1.0", "end-1c")), len=int(text_len.get("1.0", "end-1c")), id=int(text_id.get("1.0", "end-1c")), flags=int(text_flag.get("1.0", "end-1c")), frag=int(text_frag.get("1.0", "end-1c")), ttl=int(text_ttl.get("1.0", "end-1c")), proto=int(text_proto.get("1.0", "end-1c")), chksum=int(text_checksum.get("1.0", "end-1c")), options=int(text_option.get("1.0", "end-1c"))))
# ip gui
def ip_gui(custom=NO):
    global ip_p, text_count,udp_p,tcp_p,text_src,text_sprt,text_dst,text_dprt,text_hl,text_tos,text_len,text_id,text_flag,text_frag,text_ttl,text_proto,text_checksum,text_option
    udp_p = False
    tcp_p = False
    ip_p = True
    for widget in root.winfo_children():
        if widget.winfo_name() not in ("tcp", "udp", "ip", "info_dump"):
            widget.destroy()

    # src ip
    label_src = Label(root, text="SRC IP", fg="white", bg="black")
    label_src.place(x=5, y=25)
    text_src = Text(root, height=1, width=15, fg="white", bg="black", insertbackground="white")
    text_src.insert("end", "127.0.0.1")
    text_src.place(x=45, y=25)

    # dst ip
    label_dst = Label(root, text="DST IP", fg="white", bg="black")
    label_dst.place(x=5, y=50)
    text_dst = Text(root, height=1, width=15, fg="white", bg="black", insertbackground="white")
    text_dst.insert("end", "127.0.0.1")
    text_dst.place(x=45, y=50)

    # hl (header length)
    label_hl = Label(root, text="HL", fg="white", bg="black")
    label_hl.place(x=255, y=25)
    text_hl = Text(root, height=1, width=2, fg="white", bg="black", insertbackground="white")
    text_hl.insert("end", 5)
    text_hl.place(x=280, y=25)

    # tos (Type of service)
    label_tos = Label(root, text="TOS", fg="white", bg="black")
    label_tos.place(x=255, y=50)
    text_tos = Text(root, height=1, width=3, fg="white", bg="black", insertbackground="white")
    text_tos.insert("end", 0)
    text_tos.place(x=285, y=50)

    # len (length)
    label_len = Label(root, text="LEN", fg="white", bg="black")
    label_len.place(x=310, y=25)
    text_len = Text(root, height=1, width=5, fg="white", bg="black", insertbackground="white")
    text_len.insert("end", 20)
    text_len.place(x=340, y=25)

    # id (identifier)
    label_id = Label(root, text="ID", fg="white", bg="black")
    label_id.place(x=320, y=50)
    text_id = Text(root, height=1, width=6, fg="white", bg="black", insertbackground="white")
    text_id.insert("end", 0)
    text_id.place(x=340, y=50)

    # flag
    label_flag = Label(root, text="FLAG", fg="white", bg="black")
    label_flag.place(x=390, y=25)
    text_flag = Text(root, height=1, width=1, fg="white", bg="black", insertbackground="white")
    text_flag.insert("end", 0)
    text_flag.place(x=430, y=25)

    # frag (fragment)
    label_frag = Label(root, text="FRAG", fg="white", bg="black")
    label_frag.place(x=400, y=50)
    text_frag = Text(root, height=1, width=4, fg="white", bg="black", insertbackground="white")
    text_frag.insert("end", 0)
    text_frag.place(x=440, y=50)

    # ttl (time to live)
    label_ttl = Label(root, text="TTL", fg="white", bg="black")
    label_ttl.place(x=450, y=25)
    text_ttl = Text(root, height=1, width=4, fg="white", bg="black", insertbackground="white")
    text_ttl.insert("end", 64)
    text_ttl.place(x=480, y=25)

    # proto
    label_proto = Label(root, text="PROTO", fg="white", bg="black")
    label_proto.place(x=485, y=50)
    text_proto = Text(root, height=1, width=4, fg="white", bg="black", insertbackground="white")
    text_proto.insert("end", 1)
    text_proto.place(x=530, y=50)

    # checksum
    label_checksum = Label(root, text="CHECKSUM", fg="white", bg="black")
    label_checksum.place(x=525, y=25)
    text_checksum = Text(root, height=1, width=5, fg="white", bg="black", insertbackground="white")
    text_checksum.insert("end", "65535")
    text_checksum.place(x=595, y=25)

    # option
    label_option = Label(root, text="OPTION", fg="white", bg="black")
    label_option.place(x=575, y=50)
    text_option = Text(root, height=1, width=4, fg="white", bg="black", insertbackground="white")
    text_option.insert("end", 0)
    text_option.place(x=625, y=50)

    # Count
    label_count = Label(root, text="COUNT", fg="white", bg="black")
    label_count.place(x=575, y=85)
    text_count = Text(root, height=1, width=4, fg="white", bg="black", insertbackground="white")
    text_count.insert("end", 1)
    text_count.place(x=625, y=85)

    # wait for reply
    Checkbutton(root, text="Wait for reply", selectcolor="black", variable=wait_var, onvalue="wait", offvalue="", bg="black", fg="white").place(x=5, y=75)

    # buttons
    Button(root, text="Send", command=send_packet, bg="black", fg="white").place(x=117, y=75)
    Button(root, command=hex_dump, bg="black", fg="white", text="HEXDUMP").place(x=170, y=75)
    Button(root, command=show_info, bg="black", fg="white", text="SHOWINFO").place(x=250, y=75)

# udp
def udp_gui():
    global ip_p,udp_p,tcp_p
    udp_p = True
    ip_p = False
    tcp_p = False
    
    for widget in root.winfo_children():
        if widget.winfo_name() not in ("tcp", "udp", "ip", "info_dump"):
            widget.destroy()

    if ether_udp.get() == "ether_udp":
        # src mac
        label_mac_src = Label(root, text="SRC MAC", fg="white", bg="black")
        label_mac_src.place(x=5, y=85)
        text_mac_src = Text(root, height=1, width=17, fg="white", bg="black", insertbackground="white")
        text_mac_src.place(x=70, y=85)

        # dst mac
        label_mac_dst = Label(root, text="DST MAC", fg="white", bg="black")
        label_mac_dst.place(x=5, y=115)
        text_mac_dst = Text(root, height=1, width=17, fg="white", bg="black", insertbackground="white")
        text_mac_dst.place(x=70, y=115)

        # type
        label_type = Label(root, text="TYPE", fg="white", bg="black")
        label_type.place(x=220, y=85)
        text_type = Text(root, height=1, width=17, fg="white", bg="black", insertbackground="white")
        text_type.place(x=255, y=85)
    else:
        pass

    # src ip
    label_src = Label(root, text="SRC IP", fg="white", bg="black")
    label_src.place(x=5, y=25)
    text_src = Text(root, height=1, width=15, fg="white", bg="black", insertbackground="white")
    text_src.insert("end", "127.0.0.1")
    text_src.place(x=45, y=25)

    # src port
    label_sprt = Label(root, text="PRT", fg="white", bg="black")
    label_sprt.place(x=174, y=25)
    text_sprt = Text(root, height=1, width=5, fg="white", bg="black", insertbackground="white")
    text_sprt.insert("end", "80")
    text_sprt.place(x=200, y=25)
    # dst port
    label_dprt = Label(root, text="PRT", fg="white", bg="black")
    label_dprt.place(x=174, y=50)
    text_dprt = Text(root, height=1, width=5, fg="white", bg="black", insertbackground="white")
    text_dprt.insert("end", 80)
    text_dprt.place(x=200, y=50)

    # dst ip
    label_dst = Label(root, text="DST IP", fg="white", bg="black")
    label_dst.place(x=5, y=50)
    text_dst = Text(root, height=1, width=15, fg="white", bg="black", insertbackground="white")
    text_dst.insert("end", "127.0.0.1")
    text_dst.place(x=45, y=50)

    # hl (header length)
    label_hl = Label(root, text="HL", fg="white", bg="black")
    label_hl.place(x=255, y=25)
    text_hl = Text(root, height=1, width=2, fg="white", bg="black", insertbackground="white")
    text_hl.insert("end", 5)
    text_hl.place(x=280, y=25)

    # tos (Type of service)
    label_tos = Label(root, text="TOS", fg="white", bg="black")
    label_tos.place(x=255, y=50)
    text_tos = Text(root, height=1, width=3, fg="white", bg="black", insertbackground="white")
    text_tos.insert("end", 0)
    text_tos.place(x=285, y=50)

    # len (length)
    label_len = Label(root, text="LEN", fg="white", bg="black")
    label_len.place(x=310, y=25)
    text_len = Text(root, height=1, width=5, fg="white", bg="black", insertbackground="white")
    text_len.insert("end", 20)
    text_len.place(x=340, y=25)

    # id (identifier)
    label_id = Label(root, text="ID", fg="white", bg="black")
    label_id.place(x=320, y=50)
    text_id = Text(root, height=1, width=6, fg="white", bg="black", insertbackground="white")
    text_id.insert("end", 0)
    text_id.place(x=340, y=50)

    # flag
    label_flag = Label(root, text="FLAG", fg="white", bg="black")
    label_flag.place(x=390, y=25)
    text_flag = Text(root, height=1, width=1, fg="white", bg="black", insertbackground="white")
    text_flag.insert("end", 0)
    text_flag.place(x=430, y=25)

    # frag (fragment)
    label_frag = Label(root, text="FRAG", fg="white", bg="black")
    label_frag.place(x=400, y=50)
    text_frag = Text(root, height=1, width=4, fg="white", bg="black", insertbackground="white")
    text_frag.insert("end", 0)
    text_frag.place(x=440, y=50)

    # ttl (time to live)
    label_ttl = Label(root, text="TTL", fg="white", bg="black")
    label_ttl.place(x=450, y=25)
    text_ttl = Text(root, height=1, width=4, fg="white", bg="black", insertbackground="white")
    text_ttl.insert("end", 64)
    text_ttl.place(x=480, y=25)

    # proto
    label_proto = Label(root, text="PROTO", fg="white", bg="black")
    label_proto.place(x=485, y=50)
    text_proto = Text(root, height=1, width=4, fg="white", bg="black", insertbackground="white")
    text_proto.insert("end", 1)
    text_proto.place(x=530, y=50)

    # checksum
    label_checksum = Label(root, text="CHECKSUM", fg="white", bg="black")
    label_checksum.place(x=525, y=25)
    text_checksum = Text(root, height=1, width=5, fg="white", bg="black", insertbackground="white")
    text_checksum.insert("end", "65535")
    text_checksum.place(x=595, y=25)

    # option
    label_option = Label(root, text="OPTION", fg="white", bg="black")
    label_option.place(x=575, y=50)
    text_option = Text(root, height=1, width=4, fg="white", bg="black", insertbackground="white")
    text_option.insert("end", 0)
    text_option.place(x=625, y=50)

    # Count
    label_count = Label(root, text="COUNT", fg="white", bg="black")
    label_count.place(x=575, y=85)
    text_count = Text(root, height=1, width=4, fg="white", bg="black", insertbackground="white")
    text_count.insert("end", 1)
    text_count.place(x=625, y=85)

    # udp option list
    # udp len
    label_udp_len = Label(root, text="UDP LEN", fg="white", bg="black")
    label_udp_len.place(x=370, y=115)
    text_udp_len = Text(root, height=1, width=5, fg="white", bg="black", insertbackground="white")
    text_udp_len.place(x=425, y=115)

    # udp checksum
    label_udp_checksum = Label(root, text="UDP CHECKSUM", fg="white", bg="black")
    label_udp_checksum.place(x=480, y=115)
    text_udp_checksum = Text(root, height=1, width=5, fg="white", bg="black", insertbackground="white")
    text_udp_checksum.place(x=577, y=115)
    # udp len
    label_udp_len = Label(root, text="UDP LEN", fg="white", bg="black")
    label_udp_len.place(x=370, y=115)
    text_udp_len = Text(root, height=1, width=5, fg="white", bg="black", insertbackground="white")
    text_udp_len.place(x=425, y=115)

    # udp checksum
    label_udp_checksum = Label(root, text="UDP CHECKSUM", fg="white", bg="black")
    label_udp_checksum.place(x=480, y=115)
    text_udp_checksum = Text(root, height=1, width=5, fg="white", bg="black", insertbackground="white")
    text_udp_checksum.place(x=577, y=115)

    # wait for reply
    Checkbutton(root, text="Wait for reply", selectcolor="black", variable=wait_var, onvalue="wait", offvalue="", bg="black", fg="white").place(x=265, y=115)

    # buttons
    Button(root, text="Send", command=send_packet, bg="black", fg="white").place(x=220, y=115)
    Button(root, command=hex_dump, bg="black", fg="white", text="HEXDUMP").place(x=415, y=85)
    Button(root, command=show_info, bg="black", fg="white", text="SHOWINFO").place(x=500, y=85)

    # udp ether
    Checkbutton(root, text="ETHER", selectcolor="black", variable=ether_udp, command=udp_gui, onvalue="ether_udp", offvalue="", bg="black", fg="white").place(x=130, y=0)

# tcp
def tcp_gui():
    global ip_p, tcp_p, udp_p,text_tcp_options,text_urgptr,text_tcp_checksum,text_window,text_tcp_flags,text_reserved, text_ack,text_dataofs,text_seq,text_mac_src,text_mac_dst
    tcp_p = True
    udp_p = False
    ip_p = False
    

    for widget in root.winfo_children():
        if widget.winfo_name() not in ("tcp", "udp", "ip", "info_dump"):
            widget.destroy()

    if ether_tcp.get() == "ether_tcp":
        # src mac
        label_mac_src = Label(root, text="SRC MAC", fg="white", bg="black")
        label_mac_src.place(x=5, y=85)
        text_mac_src = Text(root, height=1, width=17, fg="white", bg="black", insertbackground="white")
        text_mac_src.place(x=70, y=85)

        # dst mac
        label_mac_dst = Label(root, text="DST MAC", fg="white", bg="black")
        label_mac_dst.place(x=5, y=115)
        text_mac_dst = Text(root, height=1, width=17, fg="white", bg="black", insertbackground="white")
        text_mac_dst.place(x=70, y=115)

        # type
        label_type = Label(root, text="TYPE", fg="white", bg="black")
        label_type.place(x=220, y=85)
        text_type = Text(root, height=1, width=17, fg="white", bg="black", insertbackground="white")
        text_type.place(x=255, y=85)
    else:
        pass
    
    # ip option list
    # src ip
    label_src = Label(root, text="SRC IP", fg="white", bg="black")
    label_src.place(x=5, y=25)
    text_src = Text(root, height=1, width=15, fg="white", bg="black", insertbackground="white")
    text_src.insert("end", "127.0.0.1")
    text_src.place(x=45, y=25)

    # src port
    label_sprt = Label(root, text="PRT", fg="white", bg="black")
    label_sprt.place(x=174, y=25)
    text_sprt = Text(root, height=1, width=5, fg="white", bg="black", insertbackground="white")
    text_sprt.insert("end", "80")
    text_sprt.place(x=200, y=25)

    # dst port
    label_dprt = Label(root, text="PRT", fg="white", bg="black")
    label_dprt.place(x=174, y=50)
    text_dprt = Text(root, height=1, width=5, fg="white", bg="black", insertbackground="white")
    text_dprt.insert("end", 80)
    text_dprt.place(x=200, y=50)

    # dst ip
    label_dst = Label(root, text="DST IP", fg="white", bg="black")
    label_dst.place(x=5, y=50)
    text_dst = Text(root, height=1, width=15, fg="white", bg="black", insertbackground="white")
    text_dst.insert("end", "127.0.0.1")
    text_dst.place(x=45, y=50)

    # hl (header length)
    label_hl = Label(root, text="HL", fg="white", bg="black")
    label_hl.place(x=255, y=25)
    text_hl = Text(root, height=1, width=2, fg="white", bg="black", insertbackground="white")
    text_hl.insert("end", 5)
    text_hl.place(x=280, y=25)

    # tos (Type of service)
    label_tos = Label(root, text="TOS", fg="white", bg="black")
    label_tos.place(x=255, y=50)
    text_tos = Text(root, height=1, width=3, fg="white", bg="black", insertbackground="white")
    text_tos.insert("end", 0)
    text_tos.place(x=285, y=50)

    # len (length)
    label_len = Label(root, text="LEN", fg="white", bg="black")
    label_len.place(x=310, y=25)
    text_len = Text(root, height=1, width=5, fg="white", bg="black", insertbackground="white")
    text_len.insert("end", 20)
    text_len.place(x=340, y=25)

    # id (identifier)
    label_id = Label(root, text="ID", fg="white", bg="black")
    label_id.place(x=320, y=50)
    text_id = Text(root, height=1, width=6, fg="white", bg="black", insertbackground="white")
    text_id.insert("end", 0)
    text_id.place(x=340, y=50)

    # flag
    label_flag = Label(root, text="FLAG", fg="white", bg="black")
    label_flag.place(x=390, y=25)
    text_flag = Text(root, height=1, width=1, fg="white", bg="black", insertbackground="white")
    text_flag.insert("end", 0)
    text_flag.place(x=430, y=25)

    # frag (fragment)
    label_frag = Label(root, text="FRAG", fg="white", bg="black")
    label_frag.place(x=400, y=50)
    text_frag = Text(root, height=1, width=4, fg="white", bg="black", insertbackground="white")
    text_frag.insert("end", 0)
    text_frag.place(x=440, y=50)

    # ttl (time to live)
    label_ttl = Label(root, text="TTL", fg="white", bg="black")
    label_ttl.place(x=450, y=25)
    text_ttl = Text(root, height=1, width=4, fg="white", bg="black", insertbackground="white")
    text_ttl.insert("end", 64)
    text_ttl.place(x=480, y=25)

    # proto
    label_proto = Label(root, text="PROTO", fg="white", bg="black")
    label_proto.place(x=485, y=50)
    text_proto = Text(root, height=1, width=4, fg="white", bg="black", insertbackground="white")
    text_proto.insert("end", 1)
    text_proto.place(x=530, y=50)

    # checksum
    label_checksum = Label(root, text="CHECKSUM", fg="white", bg="black")
    label_checksum.place(x=525, y=25)
    text_checksum = Text(root, height=1, width=5, fg="white", bg="black", insertbackground="white")
    text_checksum.insert("end", "65535")
    text_checksum.place(x=595, y=25)

    # option
    label_option = Label(root, text="OPTION", fg="white", bg="black")
    label_option.place(x=575, y=50)
    text_option = Text(root, height=1, width=4, fg="white", bg="black", insertbackground="white")
    text_option.insert("end", 0)
    text_option.place(x=625, y=50)

    # Count
    label_count = Label(root, text="COUNT", fg="white", bg="black")
    label_count.place(x=575, y=85)
    text_count = Text(root, height=1, width=4, fg="white", bg="black", insertbackground="white")
    text_count.insert("end", 1)
    text_count.place(x=625, y=85)

    # tcp options list
    # seq
    label_seq = Label(root, text="SEQ", fg="white", bg="black")
    label_seq.place(x=370, y=115)
    text_seq = Text(root, height=1, width=10, fg="white", bg="black", insertbackground="white")
    text_seq.place(x=400, y=115)

    # ack
    label_ack = Label(root, text="ACK", fg="white", bg="black")
    label_ack.place(x=490, y=115)
    text_ack = Text(root, height=1, width=10, fg="white", bg="black", insertbackground="white")
    text_ack.place(x=520, y=115)

    # dataofs
    label_dataofs = Label(root, text="DATAOFS", fg="white", bg="black")
    label_dataofs.place(x=610, y=115)
    text_dataofs = Text(root, height=1, width=2, fg="white", bg="black", insertbackground="white")
    text_dataofs.place(x=670, y=115)

    # reserved
    label_reserved = Label(root, text="RESERVED", fg="white", bg="black")
    label_reserved.place(x=5, y=145)
    text_reserved = Text(root, height=1, width=1, fg="white", bg="black", insertbackground="white")
    text_reserved.place(x=70, y=145)

    # tcp flags
    label_tcp_flags = Label(root, text="TCP FLAGS", fg="white", bg="black")
    label_tcp_flags.place(x=90, y=145)
    text_tcp_flags = Text(root, height=1, width=3, fg="white", bg="black", insertbackground="white")
    text_tcp_flags.place(x=160, y=145)

    # window
    label_window = Label(root, text="WINDOW", fg="white", bg="black")
    label_window.place(x=200, y=145)
    text_window = Text(root, height=1, width=5, fg="white", bg="black", insertbackground="white")
    text_window.place(x=260, y=145)

    # tcp chksum
    label_tcp_checksum = Label(root, text="TCP CHECKSUM", fg="white", bg="black")
    label_tcp_checksum.place(x=315, y=145)
    text_tcp_checksum = Text(root, height=1, width=5, fg="white", bg="black", insertbackground="white")
    text_tcp_checksum.place(x=410, y=145)

    # urgptr
    label_urgptr = Label(root, text="URGPTR", fg="white", bg="black")
    label_urgptr.place(x=465, y=145)
    text_urgptr = Text(root, height=1, width=5, fg="white", bg="black", insertbackground="white")
    text_urgptr.place(x=516, y=145)

    # tcp options
    label_tcp_options = Label(root, text="TCP OPTIONS", fg="white", bg="black")
    label_tcp_options.place(x=570, y=145)
    text_tcp_options = Text(root, height=1, width=3, fg="white", bg="black", insertbackground="white")
    text_tcp_options.place(x=650, y=145)

    # wait for reply
    Checkbutton(root, text="Wait for reply", selectcolor="black", variable=wait_var, onvalue="wait", offvalue="", bg="black", fg="white").place(x=265, y=115)

    # buttons
    Button(root, text="Send", command=send_packet, bg="black", fg="white").place(x=220, y=115)
    Button(root, command=hex_dump, bg="black", fg="white", text="HEXDUMP").place(x=415, y=85)
    Button(root, command=show_info, bg="black", fg="white", text="SHOWINFO").place(x=500, y=85)

    # udp ether
    Checkbutton(root, text="ETHER", selectcolor="black", variable=ether_tcp, command=tcp_gui, onvalue="ether_tcp", offvalue="", bg="black", fg="white").place(x=130, y=0)

# UDP, TCP
iprotocals = StringVar()
Checkbutton(root, text="IP", name="ip", selectcolor="black", variable=iprotocals, onvalue="ip", offvalue="", command=ip_gui, bg="black", fg="white").place(x=5, y=0)
Checkbutton(root, text="TCP", name="tcp", selectcolor="black", variable=iprotocals, onvalue="tcp", offvalue="", command=tcp_gui, bg="black", fg="white").place(x=40, y=0)
Checkbutton(root, text="UDP", name="udp", selectcolor="black", variable=iprotocals, onvalue="udp", offvalue="", command=udp_gui, bg="black", fg="white").place(x=85, y=0)

# info dump
text_box = Text(root, name="info_dump", height=9, bg="black", fg="white", insertbackground="white")
text_box.pack(side=BOTTOM, fill=BOTH)

class RedirectOutput:
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, text):
        self.text_widget.insert(END, text)

    def flush(self):
        pass
redirector = RedirectOutput(text_box)
sys.stdout = redirector
sys.stderr = redirector

Menu.config(root, bg="black")
root.config(bg="black")

# End
root.mainloop()
