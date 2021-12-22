######################################################
#Github: RedGrappe
######################################################
import platform, sys, glob,os,time
from time import perf_counter as timer
import threading
from subprocess import getstatusoutput
import subprocess
import terminal_banner


######################################################
banner_text = "----Traffic Merger----\nAuthor: RedGrappe\nGithub: RedGrappe\n-*-*-*-*-*-*-*-*-*-*-*-*-\nDependencies:\ntcpdump, tcpreplay, net-tools\ncapinfos, pgrep\nPython Dependencies:\nterminal_banner"
my_banner = terminal_banner.Banner(banner_text)
print(my_banner)
######################################################
banner_text2 = "----Traffic Merger----\nAuthor: RedGrappe\nGithub: RedGrappe\n-*-*-*-*-*-*WORKING-*-*-*-*-*-*-"
my_banner2 = terminal_banner.Banner(banner_text2)
######################################################
banner_text3 = "----Traffic Merger----\nAuthor: RedGrappe\nGithub: RedGrappe\n-*-*-*-*-*-*FINISHED-*-*-*-*-*-*-"
my_banner3 = terminal_banner.Banner(banner_text3)

######################################################
                #-*VARIABLES*-#
#tcpdump PID(s)
PID_Final=[]
PID=[]
NO_PROCESS=1

#Timers
timer1_start=0
timer1_actual=0
timer2_start=0
timer2_actual=0

#capture interfaces
Interfaces=[]
Interface_IP=[]

#path, folders and

PATH= getstatusoutput('pwd')
PATH= str(PATH[1])+"/"
Out_Folder=PATH+'mixed_traffic/'
FILE_FOLDER= glob.glob("*/")
AF_File=[]
AF_File_Duration=[]
Inf_File=[]
Inf_File_Duration=[]
Out_File=[]

#Misic
enter=0 
enter2=0
enter3=0
PCAP1=[]
PCAP2=[]
PCAP_E_Replay=[]
gamma=0
delta=0
Replay_Speed=int(input("Enter Replay Speed X"))
kill_tc=int(input("Enter Delay to Kill tcpdump Process: "))
######################################################
def tcpdump(CMD):subprocess.Popen( CMD)
def tcpreplay(CMD):subprocess.Popen( CMD, stdout=subprocess.PIPE )
def KILL_PID(CMD):subprocess.Popen( ['kill','-s','SIGTERM',CMD], stdout=subprocess.PIPE  )
def get_pcap_duration(al):
    output = subprocess.Popen( ['capinfos', '-u', al], stdout=subprocess.PIPE ).communicate()[0]
    output= str(output).replace("  ", ' ' )
    output=output.split(' ')
    last=float(output[-2])
    return last
def get_PID():
    #PID Gathering START#
    global PID_Final
    global PID
    global NO_PROCESS
    PID = getstatusoutput('pgrep tcpdump')
    NO_PROCESS=int(PID[0])
    PID = PID[1].split('\n')
    try:
        if len(PID) ==1 : PID_Final=PID
        else:pass
    except:
        print ("Fail Saving PID-1")
    try:
        if not len(PID) == len(PID_Final): 
            PID_Final.append(PID[len(PID)-1])       
        else:pass
    except:
        print(" error apending 2 PIDS")
    return
    #PID Gathering END#
def clear():os.system('clear')
######################################################
if not (len(sys.argv)-1) ==0:
    PASS=0
    #O.S. Verification
    try:
        if platform.system()== 'Linux':
            print ('OS: ##PASS##')
            PASS=1
    except:
        print ("OS: System not supported")

    ######################################################
    #Files Handling START#
    try:
        if len(sys.argv)-1 == 1 and PASS==1:
            Interfaces.append(sys.argv[1])
            #AF
            AF_File=glob.glob(PATH+FILE_FOLDER[0] + '*-af-p1-refilter.pcap')
            AF_File_Duration=(get_pcap_duration(str(AF_File[0])))/(Replay_Speed)
            #Inf
            Inf_File=glob.glob(PATH+FILE_FOLDER[0] + '*neris-refilter.pcap')
            Inf_File_Duration=(get_pcap_duration(Inf_File[0]))/(Replay_Speed)
            #out file
            Out_File.append(Out_Folder+str(FILE_FOLDER[0])[:-1]+"-Mixed-traffic.pcap")
            PCAP_E_Replay=(AF_File_Duration/2)-(Inf_File_Duration/2)
        elif len(sys.argv)-1 == 2:
            Interfaces=[sys.argv[1],sys.argv[2]]
            #File appending
            for i in FILE_FOLDER: 
                for x in glob.glob(PATH+i+ '*neris.pcap'):
                    if len(Inf_File)<2: Inf_File.append(x)
                for o in glob.glob(PATH+i+ '*-af-p1.pcap'):
                    if len(AF_File)<2: AF_File.append(o)
            #AF_File_Duration appending
            for u in AF_File:
                AF_File_Duration.append((get_pcap_duration(u))/(Replay_Speed))
            #Inf_File appending
            for y in Inf_File:
                Inf_File_Duration.append((get_pcap_duration(y))/(Replay_Speed))
            #out file
            for z in range(2):
                Out_File.append(Out_Folder+str(FILE_FOLDER[z])[:-1]+"-Mixed-traffic.pcap")
                PCAP_E_Replay.append((AF_File_Duration[z]/2)-(Inf_File_Duration[z]/2))
            alpha=PCAP_E_Replay[0]
            beta=PCAP_E_Replay[1]
        for q in range(2):
            try:
                cmd=['ifconfig', '-a', Interfaces[q]]
                a=subprocess.run(cmd, capture_output=True)
                b=str(a).split('\\n')
                b=b[1].split('inet ')
                b=b[1]
                b=b.split('.')
                c= b[0]+"."+b[1]+"."+b[2]+"."+"0"
                Interface_IP.append(c)
                del a
                del b
                del c
                print("Interface {} Loaded".format(Interfaces[q]))
            except:pass
        print ("duration:", Inf_File_Duration," | ", AF_File_Duration)
        '''," |\nInterface_IP: ",Interface_IP'''
        PASS+=1
    except:
        print("Folders/Files Erorr! :C")
    #Files Handling END#

    ######################################################
    #make output directory 
    if not os.path.exists(Out_Folder):
        print('Creating Out Folder')
        os.makedirs(Out_Folder)
    else:print("Out Folder Exist")

    ######################################################
    #code testing#
    
    ######################################################
    #MAIN PROCESS
    try:
        while PASS >= 2 :
            ######################################################
            #Traffic Capture and Attack Free File Replay start#
            if PASS==2 and enter==0:
                try:
                    if len(Interfaces)==1 and enter==0 :
                        #Start replay and capture of the given folder#
                        tcpd=['tcpdump', '-i', str(Interfaces[0]),'-n', '-B', '4096', 'not', 'net', str(Interface_IP[0]+"/24"), 'and', 'not', 'arp', 'and', 'not', 'ip6', 'and', 'not', 'ether', 'proto', '0x88cc', '-U', '-w', str(Out_File[0])]
                        tcpr=['tcpreplay', '-x', str(Replay_Speed), '-i', str(Interfaces[0]), str(AF_File[0])]
                        capture=threading.Thread(target=tcpdump,args=(tcpd,))
                        replay=threading.Thread(target=tcpreplay,args=(tcpr,))
                        capture.start()#TCPDUMP
                        time.sleep(5)  #DELAY
                        replay.start() #REPLAY
                        PCAP1.append(timer())
                        get_PID()
                        PCAP1.append(PID_Final[0])
                        enter=1
                        PASS=3
                        #tcpdump -i ETH5 not net 10.10.1.0/24 and not arp and not ip6 and not ether proto 0x88cc -w test.pcap
                    if len(Interfaces)==2 and enter==0 :
                        #Start replay and capture of the folders#
                        tcpd1=['tcpdump', '-i',str(Interfaces[0]), 'not', 'net', str(Interface_IP[0]+"/24"), 'and', 'not', 'arp', 'and' ,'not', 'ip6', 'and', 'not', 'ether', 'proto', '0x88cc', '-U','-w',str(Out_File[0])]
                        tcpd2=['tcpdump', '-i',str(Interfaces[1]), 'not', 'net', str(Interface_IP[1]+"/24"), 'and', 'not', 'arp', 'and' ,'not', 'ip6', 'and', 'not', 'ether', 'proto', '0x88cc', '-U','-w',str(Out_File[1])]
                        tcpr1=['tcpreplay', '-x', Replay_Speed, '-i', str(Interfaces[0]), AF_File[0]]
                        tcpr2=['tcpreplay', '-x', Replay_Speed, '-i', str(Interfaces[1]), AF_File[1]]
                        
                        capture1=threading.Thread(target=tcpdump,args=(tcpd1,))
                        capture2=threading.Thread(target=tcpdump,args=(tcpd2,))
                        replay1=threading.Thread(target=tcpreplay,args=(tcpr1,))
                        replay2=threading.Thread(target=tcpreplay,args=(tcpr2,))

                        capture1.start()
                        time.sleep(5)
                        replay1.start()
                        PCAP1.append(timer())
                        get_PID()
                        PCAP1.append(PID_Final[0])

                        capture2.start()
                        time.sleep(5)
                        replay2.start()                    
                        PCAP2.append(timer())
                        get_PID()
                        PCAP2.append(PID_Final[1])
                        enter=1
                        PASS=3
                    time.sleep(3)
                    print (PCAP1," | ",PCAP2)
                
                except: 
                    print("timing and reproduction failure")
            #Traffic Capture and Attack Free File Replay END#
            
            ######################################################
            #sync the replay of the infected traffic file Start# 
            if len(Interfaces)==1 and PASS==3 and enter==1:
                if PASS==3 and enter==1 and enter2==0:
                    actual_time=timer()
                    p1_time =actual_time-PCAP1[0]  
                    if ((p1_time) >=(PCAP_E_Replay)) and enter==1 :
                        tcpr1_Inf=['tcpreplay', '-i', str(Interfaces[0]), Inf_File[0]]
                        replay1_Inf=threading.Thread(target=tcpreplay,args=(tcpr1_Inf,))
                        replay1_Inf.start()
                        enter2 = enter2 +1
                        enter=7

            elif len(Interfaces)==2 and PASS==3 and enter==1:
                if PASS==3 and enter==1 and enter2==0:
                    actual_time=timer()
                    p1_time =actual_time-PCAP1[0]   
                    if p1_time >=PCAP_E_Replay[0] :
                        tcpr1_Inf=['tcpreplay', '-i', str(Interfaces[0]), Inf_File[0]]
                        replay1_Inf=threading.Thread(target=tcpreplay,args=(tcpr1_Inf,))
                        replay1_Inf.start()
                        enter2 = enter2 +1

                if PASS==3 and enter==1 and enter3==0:
                    actual_time=timer()
                    p2_time =actual_time-PCAP2[0]
                    if p2_time >= PCAP_E_Replay[1]:
                        tcpr2_Inf=['tcpreplay', '-i', str(Interfaces[1]), Inf_File[1]]
                        replay2_Inf=threading.Thread(target=tcpreplay,args=(tcpr2_Inf,))
                        replay2_Inf.start()
                        enter3 = enter3 +1  
                if enter2==1 and enter3 == 1:
                    enter=7 
            #sync the replay of the infected traffic file END# 

            ######################################################

            ######################################################
            #Control For Killing Process START#
            if len(Interfaces)==1 and gamma ==0:
                actual_time=timer()
                p1_time =actual_time-PCAP1[0]
                remaining="\rRemaining Time To Finish :{} Hours".format(int(AF_File_Duration-p1_time)/(3600))
                print(remaining,end='')
                del remaining
                if  p1_time-kill_tc >= AF_File_Duration:
                    print('\nkilling', FILE_FOLDER[0], 'tcpdump')
                    KILL_PID(PCAP1[1])
                    gamma=gamma + 1
            if len(Interfaces)==2:
                if gamma==0 or delta==0:
                    remaining1="\rRemaining To Finish Scenario 1 :{} Hours".format(int(AF_File_Duration[0]-p1_time)/(3600))
                    remaining2=" | Remaining To Finish Scenario 2: {} Hours".format(int(AF_File_Duration[1]-p2_time)/(3600))
                    print(remaining1,remaining2,end='')
                if gamma==0:
                    actual_time=timer()
                    p1_time =actual_time-PCAP1[0]
                    
                    
                    del remaining1
                    if  p1_time-kill_tc >= AF_File_Duration[0]:
                        clear()
                        print('\nkilling', FILE_FOLDER[0], 'Process Merge')
                        KILL_PID(PCAP1[1])
                        gamma= gamma + 1
                if delta==0:
                    actual_time=timer()
                    p2_time =actual_time-PCAP2[0]
                    
                    del remaining2
                    if  p2_time-kill_tc >= AF_File_Duration[1]:
                        clear()
                        print('\nkilling', FILE_FOLDER[1], 'Process Merge')
                        KILL_PID(PCAP2[1])
                        delta=delta + 1
            #Control For Killing Process END#
            
            ######################################################
            #cheks if we are capturing, if not ends the program :)
            get_PID()
            try:
                if NO_PROCESS==1:
                    print(my_banner3)
                    PASS=0
                    time.sleep(2)
            except:
                print("Failed exitting, Please press -* Ctl+C *-")
    except:
        print('Ups, Something Terrible Happen!! :''C ')
    #MAIN PROCESS END
else:print("Please enter minimum 1 and maximum 2 interfaces names as Arguments \nexample 1: python3 Trafic-Merger.py eth1 \nexample 2: python3 Trafic-Merger.py eth0 wlan1")
