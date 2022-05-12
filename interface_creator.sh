#!/bin/bash
echo "######################################################"
echo "#Author: Manuel Leyva "
echo "#Github: RedGrappe"
echo "#developed in ParrotOS 4.11"
echo "######################################################"
echo "RUN script like '$ sudo sh Interface_Creatir.sh'\n"
echo "Enter Virtual Interface Name | Example: ethvirtual"
read IName
echo "Enter MAC Address | Example: AA:AB:AC:AD:AE:AF"
read MAC
echo "Enter IP | Example: 10.10.1.1"
read IP

ip link add $IName type dummy
ifconfig $IName hw ether $MAC
ip addr add $IP/24 brd + dev $IName label $IName
ifconfig $IName mtu 12000 up
echo "Interfaces MTU's"
ifconfig | grep mtu
echo "Virtual Interface INFO"
ifconfig -a $IName

#if you want to revert all, use this.
#sudo ip addr del $IP/24 brd + dev $IName label $ALIAS
#sudo ip link delete IName type dummy
#sudo rmmod dummy
