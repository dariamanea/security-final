#!/bin/bash

# Please run install.sh before this and then start_server.sh in a different terminal session

 # Please use password "stirrer_hewer's" for second prompt (wamara)
 # Please input password "lure_leagued" when prompted (which is for user polypose) 


cd Client/bin 

# This will create certificates for user wamara and polypose
sudo ./getcert wamara
sudo ./getcert polypose 

#this will send the encrypted and signed message that is in input.txt from polypose to wamara 
# this will store the encrypted and signed message from input.txt in Server/users/wamara/mailbox
sudo ./sendmsg polypose wamara input.txt

#To check message, you can run ./rcvmsg and input the username polypose and password ("lure_leagued") 
#or wamara ("stirrer_hewer's"). 
sudo ./recvmsg
