from Tkinter import *
import tkMessageBox
import Tkinter
from tkFileDialog import askopenfilename
from PcapParser import PcapParser
from DGArchive import DGArchive

class DeepDAD:

    def __init__(self, *args, **kwargs):
        self.obj_dns_parser={}
        self.ftypes = [('Pcap files', '*.pcap'),    ('All files', '*'), ]
        # import tkinter
        self.top = Tkinter.Tk()
        self.top.title("DeepDAD v1.0 ")
        self.top.geometry("900x650+10+10")
        self.top.resizable(0, 0)
        # Code to add widgets will go here...
        self.rownum = 0
        self.txtfilename ={}
        self.hosts = {}
        self.domains ={}
        self.queryList ={}
        self.sel_host =""
        self.sel_domain = ""
        self.sel_query_id = ""
        self.lbl_status ={}

    def start_parse(self):

        self.lbl_status.config(text = "Status: Please wait ...........")
        self.lbl_status.update_idletasks()

        try:
            self.obj_dns_parser = PcapParser( int(self.txtmax_packet_count.get("1.0", 'end-1c')), 3, self.txtfilename.get("1.0", 'end-1c'), 1)
            self.obj_dns_parser.start_parse()
        except:
            self.lbl_status.config(text = "Status: Failed. Check file access permissions")
            return

        i = 0
        self.hosts.delete(0,END)
        #for item in self.obj_dns_parser.csv_obj.h.h.hosts:
        for item in self.obj_dns_parser.csv_obj.h.h.obj_anomaly.bot_list:
            self.hosts.insert(i, item)
            i = i + 1
            #print(item)
        # print name
        self.lbl_status.config(text = "Status: Processing completed...")

    # Browse
    def openfile_callback(self):
        name = askopenfilename(filetypes=self.ftypes)
        self.txtfilename.config(state=NORMAL)
        self.txtfilename.delete('1.0', END)
        self.txtfilename.insert(END, name)
        self.txtfilename.config(state=DISABLED)
        #print name


    # on host select
    def plot_host_query(self):
        tmp_host = self.sel_host.split("_")
        self.obj_dns_parser.csv_obj.h.h.hosts[tmp_host[0]].plot(self.sel_host)
        #self.obj_dns_parser.csv_obj.h.h.hosts[tmp_domain[0]].plot(self.obj_dns_parser.csv_obj.h.filename)

    def check_domain(self):
        obj = DGArchive(self.sel_domain)
        #print(obj.check_status())
        self.lbl_status.config(text = "Status: " + obj.check_status())

    # on host select
    def load_Domains(self,evt):
        # Note here that Tkinter passes an event object to onselect()
        w = evt.widget
        index = int(w.curselection()[0])
        self.sel_host = w.get(index)
        print 'You selected item %d: "%s"' % (index, self.sel_host)
        i=0
        self.domains.delete(0,END)
        tmp_domain = self.sel_host.split("_")
        for item in self.obj_dns_parser.csv_obj.h.h.hosts[tmp_domain[0]].domain:
            self.domains.insert(i, item)
            i = i + 1
            #print(item)


    # on Domain Select
    def load_query_list(self,evt):
        # Note here that Tkinter passes an event object to onselect()
        w = evt.widget
        index = int(w.curselection()[0])
        self.sel_domain = w.get(index)
        print 'You selected item %d: "%s"' % (index, self.sel_domain)
        i=0
        self.queryList.delete(0,END)
        tmp_host = self.sel_host.split("_")
        for item in self.obj_dns_parser.csv_obj.h.h.hosts[tmp_host[0]].domain[self.sel_domain].list:
            self.queryList.insert(i, item)
            i = i + 1
            #print(item)

    # on Query List select
    def load_req_response(self,evt):
        # Note here that Tkinter passes an event object to onselect()
        w = evt.widget
        index = int(w.curselection()[0])
        self.sel_query_id = w.get(index)
        print 'You selected item %d: "%s"' % (index, self.sel_query_id)

        tmp_host = self.sel_host.split("_")

        #print(self.obj_dns_parser.csv_obj.h.h.hosts[self.sel_host].domain[self.sel_domain].list[self.sel_query_id])
        self.txtResult.delete('1.0', END)
        self.txtResult.insert(INSERT, "-----------------------Request---------------------------")
        self.txtResult.insert(INSERT, "\nTxn ID            :       " + str(self.obj_dns_parser.csv_obj.h.h.hosts[tmp_host[0]].domain[self.sel_domain].list[self.sel_query_id].txn_id))
        self.txtResult.insert(INSERT, "\nRequest URL       :       " + str(self.obj_dns_parser.csv_obj.h.h.hosts[tmp_host[0]].domain[self.sel_domain].list[self.sel_query_id].req_url))
        self.txtResult.insert(INSERT, "\nRequest Type      :       " + str(self.obj_dns_parser.csv_obj.h.h.hosts[tmp_host[0]].domain[self.sel_domain].list[self.sel_query_id].req_type))
        self.txtResult.insert(INSERT, "\nTimestamp         :       " + str(self.obj_dns_parser.csv_obj.h.h.hosts[tmp_host[0]].domain[self.sel_domain].list[self.sel_query_id].req_timestamp))
        self.txtResult.insert(INSERT, "\nServer IP         :       " + str(self.obj_dns_parser.csv_obj.h.h.hosts[tmp_host[0]].domain[self.sel_domain].list[self.sel_query_id].dns_server_ip))

        self.txtResult.insert(INSERT, "\n-----------------------Response-------------------------")
        nonce =1

        for item in self.obj_dns_parser.csv_obj.h.h.hosts[tmp_host[0]].domain[self.sel_domain].list[self.sel_query_id].response:
            if nonce==1:
                self.txtResult.insert(INSERT, "\nResponse Code :       " + item.res_code)
                self.txtResult.insert(INSERT, "\nTTL           :       " + item.ttl)
                self.txtResult.insert(INSERT, "\nTimestamp     :       " + item.res_timestamp)
                nonce =0
            self.txtResult.insert(INSERT, "\nIP           :       " + item.resolved_ip)

    def helloCallBack(self):
        tkMessageBox.showinfo("Hello Python", "Hello World")


    def create_controls(self):
        # Row 0
        Label(self.top, text="DeepDAD v1.0",  bg='white',fg='blue', font="Times 22 bold ").grid(row=self.rownum,sticky="w", columnspan=1)
        self.lbl_status = Label(self.top, text= "Status: Idle", bg='yellow',fg='black', font="Times 14 bold ")
        self.lbl_status.grid(row=self.rownum, columnspan=2,column=1)
        self.rownum = self.rownum + 1



        # Row 1
        Label(self.top, text="Select file", font="Times 14 bold ").grid(row=self.rownum, sticky="w", column=0, columnspan=1)
        N = Button(text='Browse',fg='black', bg="green", command=self.openfile_callback).grid(row=self.rownum, sticky="w", column=1, columnspan=2)
        self.rownum = self.rownum + 1

        # Row 1a
        Label(self.top, text="Filename", font="Times 14 bold ").grid(row=self.rownum, sticky="w", column=0, columnspan=1)
        self.txtfilename = Text(height=1, width=60)
        self.txtfilename.insert(END, "C:/Users/MSingh/Google Drive/PhD/20160421_150521.pcap")
        self.txtfilename.config(state=DISABLED)
        self.txtfilename.grid(row=self.rownum, column=1,sticky="w", columnspan=2)
        self.rownum = self.rownum + 1



        # Row 1b

        Label(self.top, text="Packet Max. Count", font="Times 14 bold ").grid(row=self.rownum, pady=(0,20),sticky="w", column=0, columnspan=1)
        self.txtmax_packet_count = Text(height=1, width=20)
        self.txtmax_packet_count.insert(END, "10000")
        self.txtmax_packet_count.grid(row=self.rownum,sticky="w",pady=(0,20), column=1, columnspan=1)

        N = Button(text='Start Parse',fg='black', bg="green", command=self.start_parse).grid(row=self.rownum,pady=(0,20),sticky="w", column=2,  columnspan=1)
        self.rownum = self.rownum + 1

        # Row 2
        Label(self.top, text="Hosts",bg='blue',fg='white', font="Times 14 bold ").grid(row=self.rownum,sticky="w", column=0, columnspan=1)
        Label(self.top, text="Domains", bg='blue',fg='white', font="Times 14 bold ").grid(row=self.rownum, sticky="w",column=1, columnspan=1)
        Label(self.top, text="Query List",bg='blue',fg='white', font="Times 14 bold ").grid(row=self.rownum, sticky="w",column=2, columnspan=1)
        self.rownum = self.rownum + 1

        # Row 3
        self.hosts = Listbox(self.top, width=30,height=8)
        self.hosts.insert(1, "10.10.2.2")

        self.hosts.bind('<<ListboxSelect>>', self.load_Domains)

        self.hosts.grid(row=self.rownum,pady=(0,20), sticky="w", column=0, columnspan=1)

        # Lb1.place(bordermode=INSIDE , height=300, width=200)

        self.domains = Listbox(self.top, width=40,height=8)
        self.domains.insert(1, "Facebook.com")

        self.domains.bind('<<ListboxSelect>>', self.load_query_list)
        self.domains.grid(row=self.rownum,pady=(0,20),sticky="w", column=1)

        self.queryList = Listbox(self.top, width=30,height=8)
        self.queryList.insert(1, "10111")

        self.queryList.bind('<<ListboxSelect>>', self.load_req_response)
        self.queryList.grid(row=self.rownum,sticky="w", pady=(0,20), column=2, columnspan=1)

        self.rownum = self.rownum + 1

        # Row 4
        Label(self.top, text="Parameters", bg='blue',fg='white', font="Times 14 bold ").grid(row=self.rownum,sticky="w",column=0, columnspan=1)

        Label(self.top, text="Request Response Data", bg='blue',fg='white', font="Times 14 bold ").grid(row=self.rownum,sticky="w",column=1, columnspan=2)
        self.rownum = self.rownum + 1

        # Row 5
        self.params = Listbox(self.top, width=50, height=15)
        self.params.insert(1,"'P1' ,'No. of DNS requests per hour '")
        self.params.insert(2,"'P2' ,'No. of Distinct DNS requests '")
        self.params.insert(3,"'P3' ,'Highest No. of requests(single domain)'")
        self.params.insert(4,"'P4' ,'Average No. of requests '")
        self.params.insert(5,"'P5' ,'Highest No. of requests '")
        self.params.insert(6,"'P6' ,'No. of MX Record Queries '")
        self.params.insert(7,"'P7' ,'No. of PTR Record Queries '")
        self.params.insert(8,"'P8' ,'No. of Distinct DNS Servers '")
        self.params.insert(9,"'P9' ,'No. of Distinct TLD  Queried '")
        self.params.insert(10,"'P10' ,'No. of Distinct SLD  Queried '")
        self.params.insert(11,"'P11' ,'Uniqueness ratio '")
        self.params.insert(12,"'P12' ,'No. of Failed Queries'")
        self.params.insert(13,"'P13' ,'No. of Distinct Cities'")
        self.params.insert(14,"'P14' ,'No. of Distinct Countries '")
        self.params.insert(15,"'P15' ,'Flux ratio per hour '")
        self.params.grid(row=self.rownum, column=0,sticky="w", columnspan=1)

        #Label(self.top, width=100, height=15, text="['P1' ,'No. of DNS requests per hour ',7500]'\n'['P2' ,'No. of Distinct DNS requests ',1500]'\n'['P3' ,'Highest No. of requests(single domain)',1000]'\n'['P4' ,'Average No. of requests ',300]'\n'['P5' ,'Highest No. of requests ',500]'\n'['P6' ,'No. of MX Record Queries ',10]'\n'['P7' ,'No. of PTR Record Queries ',500]'\n'['P8' ,'No. of Distinct DNS Servers ',5]'\n'['P9' ,'No. of Distinct TLD  Queried ',25]'\n'['P10' ,'No. of Distinct SLD  Queried ',500]'\n'['P11' ,'Uniqueness ratio ',500]'\n'['P12' ,'No. of Failed Queries',12]'\n'['P13' ,'No. of Distinct Cities',70]'\n'['P14' ,'No. of Distinct Countries ',30]'\n'['P15' ,'Flux ratio per hour ',100]]").grid(row=self.rownum,column=0, columnspan=1)


        self.txtResult = Text(self.top, width=60, height=15)
        self.txtResult.grid(row=self.rownum,column=1,sticky="w", columnspan=2)
        self.rownum = self.rownum + 1

        # Row 6
        butPlot = Button(text='Plot',fg='black', bg="green", command=self.plot_host_query)
        butPlot.grid(row=self.rownum, column=0, columnspan=1)
        butDisplay = Button(text='Check Domain',fg='black', bg="green", command=self.check_domain).grid(row=self.rownum, column=1, columnspan=1)
        butFuture = Button(text='Future Use',fg='black', bg="green", command=self.openfile_callback).grid(row=self.rownum, column=2, columnspan=1)
        self.rownum = self.rownum + 1

        # Lb2.place(bordermode=INSIDE , height=400, width=300)

        self.top.mainloop()



# Create Object of BotDAD_GUI Class
objBotDad = DeepDAD()
objBotDad.create_controls()
