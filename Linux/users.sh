#! /bin/bash

senha=$1
nome=$2
number=$3
for ((i=1;i<=$number;i++)) 
do
useradd -m -d /home/$nome$i -p $(openssl passwd -1 $senha) -s /bin/bash $nome$i
usermod -aG sudo $nome$i
done