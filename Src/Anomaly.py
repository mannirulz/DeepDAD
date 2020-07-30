# Copyright (C) 2016   Manmeet Singh, Maninder Singh, Sanmeet kour
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
#
# DNS Fingerprint Parser  and Anomaly Detection for Host's DNS Fingerprint
#


import datetime
import socket
import sys
import ipaddr
import time
import dpkt
import _thread
import csv
import struct
import getopt
import os


class Anomaly:
    def __init__(self, filename):
        self.infected = 0
        self.clean_hosts = 0
        self.filename = filename
        self.counter = 1
        tmp_out_file = filename.split(".")
        self.consolidate = 0
        self.add_header =1
        self.bot_list = []

        if self.consolidate:
            self.outfile = open("output/DNS_FP_Anomaly.csv", "a+")
        else:
            self.outfile = open(tmp_out_file[0] + "_anomaly.csv", "w")

    def parse_file(self):
        req_infile = open(self.filename, "r")
        # req_infile = open("sample\\request.csv", "r")
        req_reader = csv.reader(req_infile, delimiter=',')

        count = 1
        tmpstr = ""

        for res in req_reader:
            try:
                if count == 1:
                    tmpstr += "UUID,"
                    for items in res:
                        tmpstr += items + ","
                    tmpstr = "P1,P2,P3,P4,P5,P6,P7,P8,P9,P10,P11,P12,P13,P14,P15,Result,ResCode"
                    if self.add_header == 1:
                        self.outfile.writelines(tmpstr + "\n")
                    count += 1
                    continue
                if count == 1500000:
                    break
                self.read_record(res)
                count += 1

            except:
                print ("Error reading CSV record " + str(count) , sys.exc_info())
                continue
        print ("\nNumber of infected Hosts = " + str(self.infected))
        print ("\nNumber of Clean Hosts = " + str(self.clean_hosts) + "\n")

        self.outfile.close()

    def set_bit(self,int_type, offset):
        mask = 1 << offset
        return int_type | mask

    def codetoanomaly(self, int_type):
        result = ""
        for i in range(0, 16, 1):
            mask = 1 << i
            if (mask & int_type) != 0:
                if result == "":
                    result = "A" + str(i)
                else:
                    result += ",A" + str(i)

        if result == "":
            return "-"
        else:
            return result


    def codetoanomalycount(self, int_type):
        result = 0
        for i in range(0, 16, 1):
            mask = 1 << i
            if (mask & int_type) != 0:
                result = result + 1

        return result



    def read_record(self, res):
        try:
            tmp_result = 0
            tmp_str = ""
            #query count

            host_name = res[1].split("_")[0]




            if int(res[2]) < 100:
                return

            uniqueness_ratio = ""
            #if uniquness ration divide by zero
            if int(res[23])==0:
                uniqueness_ratio = "0"
            else:
                uniqueness_ratio =  str(int(res[3]) / int(res[23]))

            tmp_param_list = res[2] + "," + res[3] + "," + res[4] + "," + res[5] + "," + res[6] + "," + res[8] + "," + \
                             res[10] + "," + res[13] + "," + res[11] + "," + res[12] + "," + str(
                int(res[2]) / int(res[3])) + "," + res[20] + "," + res[15] + "," + res[17] + "," + uniqueness_ratio  + ","


            if int(res[2]) > 7500:
                tmp_result = self.set_bit(tmp_result,1)


            # Distinct query count
            if int(res[3]) > 1500:
                tmp_result = self.set_bit(tmp_result, 2)

            # Single domain count
            if int(res[4]) > 1000:
                tmp_result = self.set_bit(tmp_result, 3)

            #bug Fix int to float
            #avg req pm
            if float(res[5]) > 300.0:
                tmp_result = self.set_bit(tmp_result, 4)

            # highest req pm revised to 1000
            if int(res[6]) > 1000:
                tmp_result = self.set_bit(tmp_result, 5)

            # MX
            if int(res[8]) > 10:
                tmp_result = self.set_bit(tmp_result, 6)

            # PTR Count
            if int(res[10]) > 500:
                tmp_result = self.set_bit(tmp_result, 7)

            # Distinct Server
            if int(res[13]) > 5:
                tmp_result = self.set_bit(tmp_result, 8)

            # TLD : revised from 25 to 50
            if int(res[11]) > 50:
                tmp_result = self.set_bit(tmp_result, 9)

            #SLD :
            if int(res[12]) > 500:
                tmp_result = self.set_bit(tmp_result, 10)

            #uniquenes ration interval <1.5 and >20 : Revised minimum from 500 to 1000
            if int(res[2]) > 1000 and (int(res[2])/int(res[3])) < 1.5:
                tmp_result = self.set_bit(tmp_result, 11)

            if int(res[2]) > 1000 and (int(res[2])/int(res[3])) > 20:
                tmp_result = self.set_bit(tmp_result, 11)


            #failed
            if int(res[20]) > 12:
                tmp_result = self.set_bit(tmp_result, 12)

            # Cities
            if int(res[15]) > 70:
                tmp_result = self.set_bit(tmp_result, 13)

            # Country
            if int(res[17]) > 30:
                tmp_result = self.set_bit(tmp_result, 14)

            # Flux ratio
            if (int(res[3]) > 1000 and int(res[23]) > 1000 and int(res[3])/int(res[23]) > 10) or (int(res[3])> 1000 and int(res[23]) > 1000 and int(res[3])/int(res[23]) < 1.10):
                tmp_result = self.set_bit(tmp_result, 15)

            tmp_str += str(self.counter) + ","

            for items in res:
                tmp_str += items + ","

            #if tmp_result == 0:
            if self.codetoanomalycount(tmp_result)<2:
                #tmp_str += "Clean," + str(tmp_result)
                tmp_param_list += "Clean," + str(tmp_result)
                out_res = tmp_str.split(",")
                out_filtered = out_res[2].split("_")
                self.clean_hosts += 1
                # print out_filtered[0] + " is Clean"
                # print tmp_str
            else:
                #tmp_str += "Bot," + str(tmp_result)
                tmp_param_list += "Bot," + str(tmp_result)
                out_res = tmp_str.split(",")
                out_filtered =  out_res[2].split("_")
                #print out_filtered[0] + " is Anomalous. Code : " + self.codetoanomaly(tmp_result)
                self.infected += 1
                self.bot_list.append(host_name+ "_" + self.codetoanomaly(tmp_result))

            self.counter += 1
                # print tmp_str
            #self.outfile.writelines(tmp_str + "\n")
            self.outfile.writelines(tmp_param_list + "\n")
        except:
            print ("Error in read_record ", sys.exc_info())


if __name__ == '__main__':
    obj = Anomaly("output/FP Db/DNS_FP_CSV.csv")
    obj.parse_file()
