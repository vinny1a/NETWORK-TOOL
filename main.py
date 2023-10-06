import tkinter as tk
import tkinter.ttk as st
import os
import sys
import socket
import threading
from datetime import datetime

window = tk.Tk()
window.title("Network Troubleshooting Tools App")
window.geometry('800x800')
window.configure(bg='white')
photo = tk.PhotoImage(
    file=r"components/Background.png")
background_label = tk.Label(window, image=photo)
background_label.place(x=0, y=0, relwidth=1, relheight=1)
w = photo.width()
h = photo.height()
window.geometry('%dx%d+0+0' % (w, h))

# Defining style
style = st.Style()

style.configure('W.TButton', font=('arial', 20, 'bold', 'underline'),
                foreground='black')
# Defining photos

photo0 = tk.PhotoImage(
    file=r"components/NetworkTools.png")
photo1 = tk.PhotoImage(
    file=r"components/PortScanner1.png")
photo2 = tk.PhotoImage(
    file=r"components/SubnetAndIPCalculator.png")
photo3 = tk.PhotoImage(
    file=r"components/Ping.png")
photo4 = tk.PhotoImage(
    file=r"components/TraceRoute.png")
photo5 = tk.PhotoImage(
    file=r"components/NsLookup.png")
photo6 = tk.PhotoImage(
    file=r"components/Scan2.png")
photo7 = tk.PhotoImage(
    file=r"components/Pingbutto.png")
photo8 = tk.PhotoImage(
    file=r"components/TraceWin.png")
photo9 = tk.PhotoImage(
    file=r"components/traceMac.png")
photo10 = tk.PhotoImage(
    file=r"components/calc.png")


# Defining the main label
tk.Label(window, text="Network Tools", bg="white", image=photo0,
         font="Helvetica 50 bold italic").pack(expand=1)
# Defining buttons
btn1 = st.Button(window, text='Port Scan', image=photo1,
                 style='W.TButton', command=lambda: openNewWindow(1))
btn1.pack(side='top')

btn2 = st.Button(window, text='Subnetting and IP calculator', image=photo2,
                 style='W.TButton', command=lambda: openNewWindow(2))
btn2.pack(side='top')

btn3 = st.Button(window, text='Ping', style='W.TButton', image=photo3,
                 command=lambda: openNewWindow(3))
btn3.pack(side='top')

btn4 = st.Button(window, text='Trace Route', image=photo4,
                 style='W.TButton', command=lambda: openNewWindow(4))
btn4.pack(side='top')

btn5 = st.Button(window, text='Nslookup',
                 style='W.TButton',  image=photo5, command=lambda: openNewWindow(5))
btn5.pack(side='top')


# logging to file
logfile = "logfile.txt"


def print_to_file(text):
    f = open('logfile.txt', 'a')
    sys.stdout = f
    print(text)


def openNewWindow(var):
    print(var)
    newWindow = tk.Toplevel(window)
    newWindow.title("New Window")
    newWindow.geometry('%dx%d+0+0' % (w, h))
    newWindow.configure(bg='white')
    background_label = tk.Label(newWindow, image=photo)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)

    def nslookup(Host_name):
        start = "The result of nslookup is "
        print('-'*70)
        try:
            # if it is not != 0 then something is wrong and raise Exception
            if os.system('nslookup {}'.format(Host_name)) == 0:
                Outputfileobject = os.popen('nslookup {}'.format(Host_name))
                Output = Outputfileobject.read()
                print_to_file(start)
                print_to_file(Output)
                Outputfileobject.close()
                label99 = tk.Label(newWindow, bg="white", text='-'*70,
                                   font=('helvetica', 20))
                label99.pack()
                label3 = tk.Label(newWindow, text=Output, bg="white",
                                  font=('helvetica', 20))
                label3.pack()
                label99 = tk.Label(newWindow, text='-'*70, bg="white",
                                   font=('helvetica', 20))
                label99.pack()
            else:
                raise Exception('Host does not exist')
        except:
            print('Command does not work')
            labelError = tk.Label(newWindow, bg="white", fg="red", text="An Error Occured! Please Close the window and try again",
                                  font=('helvetica', 15))
            labelError.pack()
        print('-'*70)

    def ping(ip):
        print('-'*60)
        start = "The result of ping is: "
        try:
            # if it is not != 0 then something is wrong and raise Exception
            if os.system('ping {}'.format(ip)) == 0:
                Outputfileobject = os.popen('ping {}'.format(ip))
                Output = Outputfileobject.read()
                print_to_file(start)
                print_to_file(Output)
                Outputfileobject.close()
                label99 = tk.Label(newWindow, text='-'*70, bg="white",
                                   font=('helvetica', 15))
                label99.pack()
                label3 = tk.Label(newWindow, text=Output, bg="white",
                                  font=('helvetica', 15))
                label3.pack()
                label99 = tk.Label(newWindow, text='-'*70, bg="white",
                                   font=('helvetica', 15))
                label99.pack()
            else:
                raise Exception('IP does not exist')
        except:
            print('Command does not work')
            labelError = tk.Label(newWindow, bg="white", fg="red", text="An Error Occured! Please Close the window and try again",
                                  font=('helvetica', 15))
            labelError.pack()
        print('-'*60)

    # Command for Window user
    def tracert(route_to_test):
        print('-'*60)
        start = "The result of traceroute is: "
        print_to_file(start)
        try:
            # if it is not != 0 then something is wrong and raise Exception
            if os.system('tracert {}'.format(route_to_test)) == 0:
                Outputfileobject = os.popen('tracert {}'.format(route_to_test))
                Output = Outputfileobject.read()
                print_to_file(Output)
                Outputfileobject.close()
                label99 = tk.Label(newWindow, text='-'*70, bg="white",
                                   font=('helvetica', 15))
                label99.pack()
                label3 = tk.Label(newWindow, text=Output, bg="white",
                                  font=('helvetica', 15))
                label3.pack()
                label99 = tk.Label(newWindow, text='-'*70, bg="white",
                                   font=('helvetica', 15))
                label99.pack()
            else:
                raise Exception('Route does not exist')
        except:
            print('Command does not work')
            labelError = tk.Label(newWindow, bg="white", fg="red", text="An Error Occured! Please Close the window and try again",
                                  font=('helvetica', 15))
            labelError.pack()
        print('-'*60)

    # Command for Mac user
    def traceroute(route_to_test):
        print('-'*60)
        start = "The result of traceroute is: "
        print_to_file(start)
        try:
            # if it is not != 0 then something is wrong and raise Exception
            if os.system('traceroute {}'.format(route_to_test)) == 0:
                Outputfileobject = os.popen(
                    'traceroute {}'.format(route_to_test))
                Output = Outputfileobject.read()

                print_to_file(Output)
                Outputfileobject.close()
                label99 = tk.Label(newWindow, text='-'*70, bg="white",
                                   font=('helvetica', 15))
                label99.pack()
                label3 = tk.Label(newWindow, text=Output, bg="white",
                                  font=('helvetica', 15))
                label3.pack()
                label99 = tk.Label(newWindow, text='-'*70, bg="white",
                                   font=('helvetica', 15))
                label99.pack()
            else:
                raise Exception('Route does not exist')
        except:
            print('Command does not work')
            labelError = tk.Label(newWindow, bg="white", fg="red", text="An Error Occured! Please Close the window and try again",
                                  font=('helvetica', 15))
            labelError.pack()
        print('-'*60)

    def portScanner(host_ip='192.168.11.1'):

        connections = []        # To run connections at the same time
        result = {}         # all
        OpenPorts = []
        try:
            # translate hostname to IPv4
            ip = socket.gethostbyname(host_ip)
            start = "The result of port scan is: "
            # prints status block of target and when the scan starts
            p1 = print("-" * 50)
            print_to_file(p1)
            p2 = print("Scanning: " + ip)
            print_to_file(p2)
            p3 = print("Scanning began at: " +
                       str(datetime.now()).split('.')[0])
            print_to_file(p3)
            p4 = print("**approximate runtime is 1 minute 30 seconds**")
            print_to_file(p4)
            p5 = print("-" * 50)
            print_to_file(p5)

            label0 = tk.Label(
                newWindow, text=("-" * 50), bg="white", font=('helvetica', 20))
            label0.pack()
            label2 = tk.Label(
                newWindow, text=("Scanning: " + ip), bg="white", font=('helvetica', 20))
            label2.pack()
            label3 = tk.Label(
                newWindow, text=("Scanning began at: " + str(datetime.now()).split('.')[0]), bg="white", font=('helvetica', 20))
            label3.pack()
            label4 = tk.Label(
                newWindow, text=("**approximate runtime is 1 minute 30 seconds**"), bg="white", font=('helvetica', 20))
            label4.pack()
            label5 = tk.Label(
                newWindow, text=("-" * 50), bg="white", font=('helvetica', 20))
            label5.pack()
            # Spawning threads to scan ports
            for a in range(65535):
                t = threading.Thread(target=TCP_connect, args=(ip, a, result))
                connections.append(t)

            # Starting threads
            for b in range(65535):
                connections[b].start()

            # Locking the main thread until all threads complete
            for c in range(65535):
                connections[c].join()

            # Printing open ports
            for d in range(65535):
                if result[d] == 'open':
                    p6 = print("Port", d, 'is', result[d])
                    print_to_file(p6)
                    label1 = tk.Label(
                        newWindow, text="Port " + str(d) + ' is ' + str(result[d]), bg="white", font=('helvetica', 20))
                    label1.pack()
                    OpenPorts.append(d)

            # Printing open ports in the list

            p7 = print("\nThe Open Ports are:", OpenPorts)
            print_to_file(p7)
            label99 = tk.Label(newWindow, text='-'*70, bg="white",
                               font=('helvetica', 20))
            label99.pack()
            label1a = tk.Label(newWindow, text="\nThe Open Ports are: " +
                               str(OpenPorts), bg="white", font=('helvetica', 20))
            label1a.pack()

            # Print out Completion time
            p8 = print("\nScanning has finished at ",
                       str(datetime.now()).split('.')[0])
            print_to_file(p8)
            label1b = tk.Label(newWindow, text="\nScanning has finished at " +
                               str(datetime.now()).split('.')[0], bg="white", font=('helvetica', 20))
            label1b.pack()
            label99 = tk.Label(newWindow, text='-'*70, bg="white",
                               font=('helvetica', 20))
            label99.pack()
        except:
            print("Error")

    def TCP_connect(ip, port, result):
        TCPsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        TCPsock.settimeout(1)
        try:
            TCPsock.connect((ip, port))
            result[port] = 'open'
        except:
            result[port] = ''

    def subnet_calculation(ip_address, subnet_mask):
        print("\n")

        # calculate subnet based on IP and subnet mask

        # convert the mask to binary string

        mask_octets_pad = []
        mask_octets_dec = subnet_mask.split(".")

        for i in range(0, len(mask_octets_dec)):
            binary_octet = bin(int(mask_octets_dec[i])).split("b")[1]

            if len(binary_octet) == 8:
                mask_octets_pad.append(binary_octet)
            elif len(binary_octet) < 8:
                binary_octect_pad = binary_octet.zfill(8)
                mask_octets_pad.append(binary_octect_pad)

            dec_mask = "".join(mask_octets_pad)

            # calculate and count num of bits in host or a subnet

            num_zeros = dec_mask.count("0")
            num_ones = (32 - num_zeros)
            num_of_hosts = abs(2 ** num_zeros - 2)

            wildcard_octets = []
            for i in mask_octets_dec:
                wi_octet = 255 - int(i)
                wildcard_octets.append(str(wi_octet))

            wildcard_mask = ".".join(wildcard_octets)

            # print(wildcard_mask)

        # convert the IP to binary

        ip_octet_pad = []
        ip_octet_dec = ip_address.split(".")

        for i in range(0, len(ip_octet_dec)):
            binary_octet = bin(int(ip_octet_dec[i])).split("b")[1]

            if len(binary_octet) < 8:
                binary_octect_pad = binary_octet.zfill(8)
                ip_octet_pad.append(binary_octect_pad)
            else:
                ip_octet_pad.append(binary_octet)

        binary_ip = "".join(ip_octet_pad)

        binary_network_address = binary_ip[:(num_ones)] + "0" * num_zeros
        # print(binary_network_address)

        binary_broadcast_address = binary_ip[:(num_ones)] + "1" * num_zeros

        # print(binary_broadcast_address)

        net_ip_octets = []
        for i in range(0, len(binary_network_address), 8):
            n_ip_octet = binary_network_address[i:i+8]
            net_ip_octets.append(n_ip_octet)

        net_ip_address = []
        for i in net_ip_octets:
            net_ip_address.append(str(int(i, 2)))

        network_address = ".".join(net_ip_address)

        max_ip_octets = []
        for i in range(0, len(binary_broadcast_address), 8):
            m_ip_octets = binary_broadcast_address[i:i+8]
            max_ip_octets.append(m_ip_octets)

        max_ip_address = []
        for i in max_ip_octets:
            max_ip_address.append(str(int(i, 2)))

        broadcast_address = ".".join(max_ip_address)

        # printing all the results
        start = "The result of subnet calcualtion: "
        print_to_file(start)
        p2 = print("Network address is: %s" % network_address)
        print_to_file(p2)
        p3 = print("Broadcast address is: %s" % broadcast_address)
        print_to_file(p3)
        p4 = print("Number of hosts in subnet: %s" % num_of_hosts)
        print_to_file(p4)
        p5 = print("Wildcard mask is: %s " % wildcard_mask)
        print_to_file(p5)
        p6 = print("Mask bit is: %s " % num_ones)
        print_to_file(p6)
        label99 = tk.Label(newWindow, text='-'*70,
                           font=('helvetica', 10))
        label99.pack()
        label0 = tk.Label(
            newWindow, text=("Network address is" + str(network_address)), bg="white", font=('helvetica', 20))
        label0.pack()
        label2 = tk.Label(
            newWindow, text=("Broadcast address is" + str(broadcast_address)), bg="white", font=('helvetica', 20))
        label2.pack()
        label3 = tk.Label(
            newWindow, text=("Number of hosts in subnet:" + str(num_of_hosts)), bg="white", font=('helvetica', 20))
        label3.pack()
        label4 = tk.Label(
            newWindow, text=("Wildcard mask is: " + str(wildcard_mask)), bg="white", font=('helvetica', 20))
        label4.pack()
        label5 = tk.Label(
            newWindow, text=("Mask bit is: " + str(num_ones)), bg="white", font=('helvetica', 20))
        label5.pack()
        label99 = tk.Label(newWindow, text='-'*70, bg="white",
                           font=('helvetica', 20))
        label99.pack()

    #
    if var == 1:
        newWindow.title("Port Scan")
        tk.Label(newWindow,
                 text="Port Scan", image=photo1, bg="white",
                 font="Helvetica 50 bold italic").pack()

        canvas1 = tk.Canvas(newWindow, bg="white", width=200, height=200)
        canvas1.pack()

        label1 = tk.Label(newWindow, bg="white", text='Type your IP Address:')
        label1.config(font=('helvetica', 20))
        canvas1.create_window(100, 100, window=label1)

        entry1 = tk.Entry(newWindow, font=("default", 20))
        canvas1.create_window(100, 140, window=entry1)

        btn1 = st.Button(newWindow, text='Scan', image=photo6,
                         style='W.TButton', command=lambda: portScanner(entry1.get()))
        btn1.pack(side='top')
    elif var == 2:
        newWindow.title("Subnetting and IP calculator")
        tk.Label(newWindow,
                 text="Subnetting and \n IP calculator", image=photo2, fg="black", bg="white",
                 font="Helvetica 50 bold italic").pack()

        canvas2 = tk.Canvas(newWindow, bg="white", width=200, height=300)
        canvas2.pack()

        label2 = tk.Label(newWindow, bg="white", text='Type your IP Address:')
        label2.config(font=('helvetica', 10))
        canvas2.create_window(100, 100, window=label2)

        entry2 = tk.Entry(newWindow, font=("default", 20))
        canvas2.create_window(100, 140, window=entry2)

        label2a = tk.Label(newWindow, bg="white",
                           text='Type your Subnet Mask:')
        label2a.config(font=('helvetica', 10))
        canvas2.create_window(100, 200, window=label2a)

        entry2a = tk.Entry(newWindow, font=("default", 20))
        canvas2.create_window(100, 240, window=entry2a)

        btn2 = st.Button(newWindow, text='Scan', image=photo10,
                         style='W.TButton', command=lambda: subnet_calculation(entry2.get(), entry2a.get()))
        btn2.pack(side='top')
    elif var == 3:
        newWindow.title("Ping")
        tk.Label(newWindow,
                 text="Ping", image=photo3, fg="black", bg="white",
                 font="Helvetica 50 bold italic").pack()
        canvas3 = tk.Canvas(newWindow, bg="white", width=200, height=200)
        canvas3.pack()

        label3 = tk.Label(newWindow, bg="white", text='Type your IP Address:')
        label3.config(font=('helvetica', 10))
        canvas3.create_window(100, 100, window=label3)

        entry3 = tk.Entry(newWindow, font=("default", 20))
        canvas3.create_window(100, 140, window=entry3)

        btn3 = st.Button(newWindow, text='Ping', image=photo7,
                         style='W.TButton', command=lambda: ping(entry3.get()))
        btn3.pack(side='top')
    elif var == 4:
        newWindow.title("Trace Route")
        tk.Label(newWindow,
                 text="Trace Route", image=photo4, fg="black", bg="white",
                 font="Helvetica 50 bold italic").pack()
        canvas4 = tk.Canvas(newWindow, bg="white", width=200, height=200)
        canvas4.pack()

        label4 = tk.Label(newWindow, bg="white", text='Type your route:')
        label4.config(font=('helvetica', 10))
        canvas4.create_window(100, 100, window=label4)

        entry4 = tk.Entry(newWindow, font=("default", 20))
        canvas4.create_window(100, 140, window=entry4)

        btn4 = st.Button(newWindow, text='Scan for windows', image=photo8,
                         style='W.TButton', command=lambda: tracert(entry4.get()))
        btn4.pack(side='top')
        btn4a = st.Button(newWindow, text='Scan for Mac', image=photo9,
                          style='W.TButton', command=lambda: traceroute(entry4.get()))
        btn4a.pack(side='top')
    else:
        newWindow.title("Nslookup")
        tk.Label(newWindow,
                 text="Nslookup", image=photo5, bg="white", fg="black",
                 font="Helvetica 50 bold italic").pack()
        canvas5 = tk.Canvas(newWindow, bg="white", width=200, height=200)
        canvas5.pack()

        label5 = tk.Label(newWindow, bg="white", text='Type your IP Address:')
        label5.config(font=('helvetica', 10))
        canvas5.create_window(100, 100, window=label5)

        entry5 = tk.Entry(newWindow, font=("default", 20))
        canvas5.create_window(100, 140, window=entry5)

        btn5 = st.Button(newWindow, text='Scan', image=photo6,
                         style='W.TButton', command=lambda: nslookup(entry5.get()))
        btn5.pack(side='top')


window.mainloop()
