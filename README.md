# DeepDAD (Deep learning based Bot DNS Anomaly Detector)
DeepDAD is a GUI based Bots DNS Anomaly detection tool which considers multipoint anomaly detection and uses deep learning algorithms for machine learning

(Tested on Windows 10 64 bit. Should work for Linux and other Windows versions)

---------------------------------
I - Installation Instruction 
---------------------------------

1. Install Python 2.7.9 (https://www.python.org/downloads/release/python-279/)
2. Install Pycharm Community Edition (Optional)
3. Install Following Packages

      a) python -m pip install ipaddr
  
      b) python -m pip install dpkt
  
      c) python -m pip install geoip2
  
      d) python -m pip install matplotlib
      
      (Note: in case of error, upgrade pip to latest version using this command : python -m pip install -U pip)
      
      e)  python -m pip install win_inet_pton
 
---------------------------------
II- Dataset Preparation
---------------------------------
 
 1. Filter all DNS traffic from Pcap file as tool analyses DNS packets only using command below :
 
    c:\Progra~1\Wireshark\tshark.exe  -r "input.pcap" -F pcap -Y dns -t ad -w "big.pcap"
 
 2. Convert a bigger pcapfile to 1 hour duration using the command below as fingerprint are calculated for one hour:
 
     c:\Progra~1\Wireshark\editcap.exe -F pcap -i 3600 "big.pcap"  "slice.pcap"
 
                  OR
 
  1.     Download the sample file (20160421_150521.pcap) from link below:

       https://drive.google.com/file/d/14cRY6aEQz_xVsfySBb4Ik6mPYDLoIc88/view?usp=sharing

                  OR

  1.     Download sample file from Mendeley Dataset from link below:

       https://data.mendeley.com/datasets/zh3wnddzxy/1
 
 
 ---------------------------------
 Running BotDAD
 ---------------------------------
 
 1. Download and extract the zip from the github repository to DeepDAD Folder
 
 2.  <<botDAD_Path>>:>    C:\python27\Python.exe GUI.py
     
 
     
        
 

 

6. Following files will be generated at the successful completion of the script
 
    a) In the same folder as the pcap file
    
                  DNS Requests    : 20160421_150521.pcap_req.csv

                  DNS Response    : 20160421_150521.pcap_res.csv

                  PCap Parser Log : 20160421_150521.pcap_log.csv
      
      
     b) In the Output folder
     
                 Hosts DNS fingerpeint : DNS_FP.csv

                 Anomaly detection     : DNS_FP_Anomaly.csv
     
       
 
 For BotDAD machine learning module please refer readme file from link below:
 
 https://github.com/mannirulz/BotDAD/blob/master/ML/Readme.MD
