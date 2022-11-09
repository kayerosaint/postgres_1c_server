#!/bin/bash

#######################################
# Script for install postgres + 1C server
# on Ubuntu 22.04
# compatible with Ansible
# Made by Maksim Kulikov, 2022
#######################################

## COLORS ##
# Reset
Color_Off='\033[0m'       # Text Reset

# Regular Colors
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Cyan='\033[0;36m'         # Cyan

## Directives ##

TEMP_FILE=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^TEMP_FILE/{v=t($2)};END{printf "%s\n",v}' env)
# Look for your system filename here /etc/netplan/
NETPLAN_SYSTEM_FILE=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^NETPLAN_SYSTEM_FILE/{v=t($2)};END{printf "%s\n",v}' env)
# Your config
NETPLAN_MY_FILE=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^NETPLAN_MY_FILE/{v=t($2)};END{printf "%s\n",v}' env)
CUR_DIR=$(pwd)
KEY_SSH=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^KEY_SSH/{v=t($2)};END{printf "%s\n",v}' env)
POSTGRES_PASSWORD=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^POSTGRES_PASSWORD/{v=t($2)};END{printf "%s\n",v}' env)
# Script path
IPTABLES_PATH=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^IPTABLES_PATH/{v=t($2)};END{printf "%s\n",v}' env)
MASK=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^MASK/{v=t($2)};END{printf "%s\n",v}' env)
IFACE=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^IFACE/{v=t($2)};END{printf "%s\n",v}' env)
SSH_PORT=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^SSH_PORT/{v=t($2)};END{printf "%s\n",v}' env)
RSA_NAME=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^RSA_NAME/{v=t($2)};END{printf "%s\n",v}' env)
USERNAME_SSH=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^USERNAME_SSH/{v=t($2)};END{printf "%s\n",v}' env)
# for server
PORTS_1=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^PORTS_1/{v=t($2)};END{printf "%s\n",v}' env)
# BD
PORTS_2=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^PORTS_2/{v=t($2)};END{printf "%s\n",v}' env)

# For network
NETWORK=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^NETWORK/{v=t($2)};END{printf "%s\n",v}' env)
MAIN_IP=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^MAIN_IP/{v=t($2)};END{printf "%s\n",v}' env)
GATEWAY=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^GATEWAY/{v=t($2)};END{printf "%s\n",v}' env)
DNS_NAMESERVERS=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^DNS_NAMESERVERS/{v=t($2)};END{printf "%s\n",v}' env)
NETMASK=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^NETMASK/{v=t($2)};END{printf "%s\n",v}' env)
HOSTNAME=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^HOSTNAME/{v=t($2)};END{printf "%s\n",v}' env)
WHITE_IP=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^WHITE_IP/{v=t($2)};END{printf "%s\n",v}' env)

## Functions ##
# Run a command in the background.
_evalBgr() {
    eval "$@" &>/dev/null & disown;
}

# Dirs
touch='if [ 1 == 1 ]; then sudo touch $1; fi'
(set -- /etc/network/interfaces && eval "$touch" ; set -- $TEMP_FILE && eval "$touch" ; set -- /etc/iptables_rules && eval "$touch") && sudo chmod 0777 $TEMP_FILE
# For logs
  exec 2>logs+errors

# Set HostName
echo -e "$Cyan \n Set hostname $Color_Off"
sleep 1 ; sudo hostnamectl set-hostname $HOSTNAME &&
#############in_dev################
COUNTER_1=$(echo -e "SET HOSTNAME: $Green SUCCESS $Color_Off") || COUNTER_1=$(echo -e "SET HOSTNAME: $Red FALSE $Color_Off")
#############in_dev################
echo -e "$Green \n Done $Color_Off" ; sleep 1

# Edit host file
echo -e "$Cyan \n Editing host file $Color_Off"
{ if [ -d "$TEMP_FILE" ]; then
    echo "$TEMP_FILE already exist!"
  elif [ ! -d "$TEMP_FILE" ]; then
    sudo touch $TEMP_FILE && sudo chmod 0777 $TEMP_FILE & echo "" > $TEMP_FILE
  fi
sudo chmod 0777 /etc/hosts && echo "" > $TEMP_FILE ;
awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^MAIN_IP/{m=t($2)};/^HOSTNAME/{h=t($2)};END{printf "%s   %s\n",m,h}' $CUR_DIR/env >> /etc/hosts ;
awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^WHITE_IP/{m=t($2)};/^HOSTNAME/{h=t($2)};END{printf "%s   %s\n",m,h}' $CUR_DIR/env >> /etc/hosts ;
wait ; sudo awk '!seen[$0]++' /etc/hosts > $TEMP_FILE && wait ; cat $TEMP_FILE > /etc/hosts && sudo chmod 0755 /etc/hosts ; } &&
#############in_dev################
  COUNTER_2=$(echo -e "EDITING HOST FILE: $Green SUCCESS $Color_Off") || COUNTER_2=$(echo -e "EDITING HOST FILE: $Red FALSE $Color_Off")
#############in_dev################
sleep 1 ; echo -e "$Green \n Done $Color_Off"

# Install tools
echo -e "$Cyan \n Begin install soft/tools and update system... $Color_Off"
{ { echo -e "y" | { sudo apt install net-tools mc curl ; sudo apt-get install htop iptables-persistent sshpass gnupg2 ; } ; } ;
# Install atom
wget -qO - https://packagecloud.io/AtomEditor/atom/gpgkey | sudo apt-key add - ;
sudo sh -c 'echo "deb [arch=amd64] https://packagecloud.io/AtomEditor/atom/any/ any main" > /etc/apt/sources.list.d/atom.list' ;
{ { echo -e "y" | { sudo apt-get update && sudo apt-get install atom && sudo apt-get install atom-beta ; } ; } ; } ;
# Update/upgrade
sudo apt update && sudo apt upgrade && sudo apt full-upgrade && sudo apt autoremove ;
echo -e "$Yellow \n done $Color_Off" ; sleep 1 ; } &&
#############in_dev################
COUNTER_3=$(echo -e "INSTALL SOFT/TOOLS: $Green SUCCESS $Color_Off") || COUNTER_3=$(echo -e "INSTALL SOFT/TOOLS: $Red FALSE $Color_Off") ;
#############in_dev################

# Install network via NETPLAN
{ echo -e "$Cyan \n Your current network $Color_Off" ; sudo lshw -C network ;
echo -e "$Cyan \n Begin install network setings with NETPLAN $Color_Off" ; sleep 1 ;
sudo chmod 0777 /etc/netplan/$NETPLAN_SYSTEM_FILE ;
# ! - not
if ! grep -q "MYCONFIG" /etc/netplan/$NETPLAN_SYSTEM_FILE ; then
  cat $CUR_DIR/$NETPLAN_MY_FILE > /etc/netplan/$NETPLAN_SYSTEM_FILE && sudo systemctl start systemd-networkd && sudo netplan generate && sudo netplan apply && echo -e "$Green \n Done $Color_Off"
else
  echo -e "$Green \n Done $Color_Off"
fi ; } &&
#############in_dev################
COUNTER_4=$(echo -e "CONFIGURE NETWORK VIA NETPLAN: $Green SUCCESS $Color_Off") || COUNTER_4=$(echo -e "CONFIGURE NETWORK VIA NETPLAN: $Red FALSE $Color_Off")
#############in_dev################

# Fix some problemls with connections
{ echo -e "$Cyan \n Begin fix problem with connections, if persists $Color_Off" ;
sleep 1 ; wget -q --spider http://ya.ru ;
if [ $? -eq 0 ]; then
    echo -e "$Green \n Everything OK! $Color_Off"
else
  echo -e "$Red \n No connection, begin fixing... $Color_Off" ; sleep 1 ;
  sudo ifconfig $IFACE up && sudo ip addr add $MAIN_IP/$MASK dev $IFACE && ip r sh && sudo route add default gw $GATEWAY && sudo chmod 0777 /etc/resolv.conf ;
  if [ -d "$TEMP_FILE" ]; then
    echo "$TEMP_FILE already exist!"
  elif [ ! -d "$TEMP_FILE" ]; then
    sudo touch $TEMP_FILE && sudo chmod 0777 $TEMP_FILE
  fi
  echo "" > $TEMP_FILE && echo "nameserver $DNS_NAMESERVERS" >> /etc/resolv.conf && sudo awk '!seen[$0]++' /etc/resolv.conf > $TEMP_FILE && cat $TEMP_FILE > /etc/resolv.conf
fi
# Restart network manager
echo -e "$Cyan \n restart network manager... $Color_Off" ;
sudo systemctl restart NetworkManager ; sleep 1 ; echo -e "$Green \n Done $Color_Off" ; } &&
#############in_dev################
COUNTER_5=$(echo -e "NETWORK CHECK: $Green SUCCESS $Color_Off") || COUNTER_5=$(echo -e "NETWORK CHECK: $Red FALSE $Color_Off")
#############in_dev################

# Install ssh
{ echo -e "$Cyan \n Begin install SSH... $Color_Off" ;
sleep 1 ; sudo apt install openssh-server && sudo /lib/systemd/systemd-sysv-install enable ssh ;
# ! - not
if ! grep -q "$SSH_PORT" /etc/ssh/sshd_config ; then
  sudo sed -i "s/#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
  sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
  echo -e "$Green \n Done $Color_Off"; sleep 1
else
  echo -e "$Green \n Done $Color_Off"; sleep 1
fi

# SSH generation
echo -e "$Green \n Begin generation... $Color_Off" ;
# Force overwrite enable!
sleep 1 ; echo -e 'y\n' | ssh-keygen -f /home/$USERNAME_SSH/.ssh/rsa-$RSA_NAME -t rsa -N '' && sudo systemctl restart sshd ;
echo -e "$Green \n Done $Color_Off" ;
echo -e "$Green \n copy key on server... $Color_Off"; sleep 1 ; sudo chmod +x $CUR_DIR/ssh_pass.sh ;
{ S_PASS="$KEY_SSH" SSH_ASKPASS="$CUR_DIR/ssh_pass.sh" setsid -w ssh-copy-id -p $SSH_PORT -i /home/$USERNAME_SSH/.ssh/rsa-$RSA_NAME.pub $USERNAME_SSH@$MAIN_IP ; } ; sudo chmod 0400 $CUR_DIR/ssh_pass.sh ; echo -e "$Green \n Done $Color_Off" ; } &&
#############in_dev################
COUNTER_6=$(echo -e "SSH INSTALLATION: $Green SUCCESS $Color_Off") || COUNTER_6=$(echo -e "SSH INSTALLATION: $Red FALSE $Color_Off")
#############in_dev################

# Login setup
{ echo -e "$Cyan \n Continue configure SSH... $Color_Off" ;
sudo sed -i 's/#PubkeyAuthentication no/PubkeyAuthentication yes/' /etc/ssh/sshd_config ; sudo sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config ;
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config ; sudo sed -i 's/#PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config ;
sleep 1 ; echo -e "$Green \n Done $Color_Off" ;
# Restart ssh
echo -e "$Cyan \n Begin restart ssh... $Color_Off" ; sleep 1 ; sudo systemctl restart ssh && echo -e "$Green \n Done $Color_Off" ; sleep 1 ;

# Login background check/out
echo -e "$Cyan \n Try login via ssh... $Color_Off" ;
echo "" > $TEMP_FILE; sleep 1 ;
cmd="sshpass -p "$KEY_SSH" ssh -p $SSH_PORT $USERNAME_SSH@$MAIN_IP > $TEMP_FILE &";
_evalBgr "${cmd}"; sleep 1 ;
export_data=$(<$TEMP_FILE); grep -q "Welcome to" $TEMP_FILE; [ $? -eq 0 ] && echo ">>> SUCCESS CONNECTION <<<" || echo "??? ERROR CONNECTION ???" ; sleep 2 ; } &&
if grep -q "Welcome to" $TEMP_FILE ; then
  COUNTER_7=$(echo -e "SSH LOGIN: $Green SUCCESS $Color_Off")
else
  COUNTER_7=$(echo -e "SSH LOGIN: $Red FAIL $Color_Off")
fi
# Configure SSH
{ echo -e "$Cyan \n Continue configure SSH... $Color_Off" ;
if ! grep -q "Host $RSA_NAME" /home/$USERNAME_SSH/.ssh/config; then
  echo "Host $RSA_NAME" >>  /home/$USERNAME_SSH/.ssh/config ;
elif ! grep -q "User $USERNAME_SSH" /home/$USERNAME_SSH/.ssh/config; then
  echo "User $USERNAME_SSH" >> /home/$USERNAME_SSH/.ssh/config ;
elif ! grep -q "HostName $MAIN_IP" /home/$USERNAME_SSH/.ssh/config; then
  echo "HostName $MAIN_IP" >> /home/$USERNAME_SSH/.ssh/config ;
elif ! grep -q "IdentityFile /home/$USERNAME_SSH/.ssh/rsa-$RSA_NAME" /home/$USERNAME_SSH/.ssh/config; then
  echo "IdentityFile /home/$USERNAME_SSH/.ssh/rsa-$RSA_NAME" >> /home/$USERNAME_SSH/.ssh/config ;
elif ! grep -q "Port $SSH_PORT" /home/$USERNAME_SSH/.ssh/config; then
  echo "Port $SSH_PORT" >> /home/$USERNAME_SSH/.ssh/config ; echo -e "$Green \n Done $Color_Off" ; sleep 1 ;
else
  echo -e "$Green \n Done $Color_Off" ; sleep 1
fi ; } &&
#############in_dev################
COUNTER_8=$(echo -e "SSH CONFIGURATION: $Green SUCCESS $Color_Off") || COUNTER_8=$(echo -e "SSH CONFIGURATION: $Red FALSE $Color_Off")
#############in_dev################

#Configure iptables_firewall
{ echo -e "$Cyan \n Begin configure IPTABLES FIREWALL... $Color_Off" ;
# Check path
if [ -d "$IPTABLES_PATH" ]; then
  echo "$IPTABLES_PATH already exist!"
elif [ ! -d "$IPTABLES_PATH" ]; then
  sudo touch $IPTABLES_PATH ; sudo chmod 0777 $IPTABLES_PATH ; sudo chmod 0777 /sbin/iptables-save ; sudo chmod 0777 /etc/iptables_rules
fi
if ! grep -q "$PORTS_1" $IPTABLES_PATH; then
# for server
  echo "iptables -I INPUT 1 -p tcp --dport $PORTS_1 -j ACCEPT" >> $IPTABLES_PATH ;
elif ! grep -q "$PORTS_2" $IPTABLES_PATH; then
  echo "#!/bin/bash" >> $IPTABLES_PATH ;
  # BD
  echo "iptables -I INPUT 1 -p tcp --dport $PORTS_2 -j ACCEPT" >> $IPTABLES_PATH ;
  # path rules
  echo "/sbin/iptables-save > /etc/iptables_rules" >> $IPTABLES_PATH ;
  echo -e "$Green \n Done $Color_Off" ; sleep 1 ;
else
  echo -e "$Green \n Done $Color_Off" ; sleep 1 ;
fi

# Check rules
echo -e "$Cyan \n Check/Run rules... $Color_Off" ;
if [ -d "/run/xtables.lock" ]; then
  echo "/run/xtables.lock already exist!"
elif [ ! -d "/run/xtables.lock" ]; then
  sudo touch /run/xtables.lock
fi
sudo /bin/bash $IPTABLES_PATH && sudo iptables -L -v -n ; sleep 1 ; echo -e "$Green \n Done $Color_Off" ; sleep 1 ; } &&
#############in_dev################
COUNTER_9=$(echo -e "IPTABLES SETUP: $Green SUCCESS $Color_Off") || COUNTER_9=$(echo -e "IPTABLES SETUP: $Red FALSE $Color_Off")
#############in_dev################

# Save rules
{ echo -e "$Cyan \n Save IPTABLES rules... $Color_Off" ;
sudo netfilter-persistent save && sudo /sbin/iptables-save > /etc/iptables_rules ; echo -e "$Green \n Done $Color_Off" ; sleep 1 ;

# Additional configure for iptables
echo -e "$Cyan \n Additional configure for iptables $Color_Off" ;
sudo depmod -a && sudo modprobe ip_tables && sudo iptables -nL && echo -e "$Green \n Done $Color_Off" ; sleep 1 ; } &&
#############in_dev################
COUNTER_10=$(echo -e "ADDITIONAL CONFIGURATION FOR IPTABLES: $Green SUCCESS $Color_Off") || COUNTER_10=$(echo -e "ADDITIONAL CONFIGURATION FOR IPTABLES: $Red FALSE $Color_Off")
#############in_dev################

# Fix priviliges
{ echo -e "$Cyan \n Fix priviliges $Color_Off" ;
sudo chmod 0755 /etc/iptables_rules; sudo chmod 0755 /etc/resolv.conf ;
sudo chmod 0755 /etc/netplan/$NETPLAN_SYSTEM_FILE ; echo -e "$Green \n Done $Color_Off" ; sleep 1 ; } &&
{ stat -c "%a" /etc/iptables_rules /etc/resolv.conf /etc/netplan/$NETPLAN_SYSTEM_FILE > $TEMP_FILE && cat $TEMP_FILE | tr -d '\n' ; } &>/dev/null && if echo "755755755" &>/dev/null ; then
  COUNTER_11=$(echo -e "EDIT CREDENTIALS: $Green SUCCESS $Color_Off")
else
  COUNTER_11=$(echo -e "EDIT CREDENTIALS: $Red FAIL $Color_Off")
fi

# Set locale
{ echo -e "$Cyan \n Reconfigure locales/example "ru_RU.UTF-8 UTF-8" $Color_Off" ; sleep 1 ; sudo dpkg-reconfigure locales ;
echo -e "$Green \n Done $Color_Off" ; sleep 1 ; } &&
#############in_dev################
COUNTER_12=$(echo -e "RECONFIGURE LOCALES: $Green SUCCESS $Color_Off") || COUNTER_12=$(echo -e "RECONFIGURE LOCALES: $Red FALSE $Color_Off")
#############in_dev################

# Instal postgres for 1c.postgres.ru
{ echo -e "$Cyan \n Instal postgres $Color_Off"
wget https://repo.postgrespro.ru/1c-15/keys/pgpro-repo-add.sh ; sudo chmod 0777 $CUR_DIR/pgpro-repo-add.sh & sudo sh pgpro-repo-add.sh ;
# Install BD
sudo apt-get install postgrespro-1c-15 ;
# Autorun enable
sudo systemctl enable postgrespro-1c-15 ;
# Stop service
sudo systemctl stop postgrespro-1c-15 ;
{ sudo chmod 0777 /var/lib/pgpro/1c-15/data/ && sudo rm -rf /var/lib/pgpro/1c-15/data/* ; sudo /opt/pgpro/1c-15/bin/pg-setup initdb --tune=1c --locale=ru_RU.UTF-8 ;
sudo systemctl start postgrespro-1c-15 ; echo -e "$Green \n Done $Color_Off" ; } && wait ;

# Set password for postgres
echo -e "$Yellow \n Enter password for postgres $Color_Off" ;
sudo -i -u postgres psql -U postgres -d template1 -c "ALTER USER postgres PASSWORD '$POSTGRES_PASSWORD'" \; history -d $((HISTCMD-1)) ;
echo -e "$Green \n Done $Color_Off" ; sleep 1 ; } &&
#############in_dev################
COUNTER_13=$(echo -e "INSTALL POSTGRES: $Green SUCCESS $Color_Off") || COUNTER_13=$(echo -e "INSTALL POSTGRES: $Red FALSE $Color_Off")
#############in_dev################

## Install 1C server
{ echo -e "$Cyan \n Install 1C server $Color_Off" ;
sudo apt-get install imagemagick \ unixodbc \ ttf-mscorefonts-installer \ ; wait ; sudo chmod 0777 /etc/apt/sources.list ;
PATH_REP="deb http://cz.archive.ubuntu.com/ubuntu focal main universe" ;
# Update lib
echo -e "$Cyan \n Please wait... $Color_Off" ; sudo sed -i "s|$PATH_REP||g" /etc/apt/sources.list && echo "$PATH_REP" >> /etc/apt/sources.list ;
sudo apt update && sudo apt install libenchant1c2a ; wait ; } &&
#############in_dev################
COUNTER_14=$(echo -e "INSTALL 1C: $Green SUCCESS $Color_Off") || COUNTER_14=$(echo -e "INSTALL 1C: $Red FALSE $Color_Off")
#############in_dev################

echo -e "$Yellow \n CHECK SCRIPT BEFORE INSTALLATION $Color_Off"
COUNTER=1
while [  $COUNTER -lt 15 ]; do
    if [[ $COUNTER == 1 ]] ; then
       echo "$COUNTER_1" ; sleep 1
    elif [[ $COUNTER == 2 ]] ; then
       echo "$COUNTER_2" ; sleep 1
    elif [[ $COUNTER == 3 ]] ; then
       echo "$COUNTER_3" ; sleep 1
    elif [[ $COUNTER == 4 ]] ; then
       echo "$COUNTER_4" ; sleep 1
    elif [[ $COUNTER == 5 ]] ; then
       echo "$COUNTER_5" ; sleep 1
    elif [[ $COUNTER == 6 ]] ; then
       echo "$COUNTER_6" ; sleep 1
    elif [[ $COUNTER == 7 ]] ; then
       echo "$COUNTER_7" ; sleep 1
    elif [[ $COUNTER == 8 ]] ; then
       echo "$COUNTER_8" ; sleep 1
    elif [[ $COUNTER == 9 ]] ; then
       echo "$COUNTER_9" ; sleep 1
    elif [[ $COUNTER == 10 ]] ; then
       echo "$COUNTER_10" ; sleep 1
    elif [[ $COUNTER == 11 ]] ; then
       echo "$COUNTER_11" ; sleep 1
    elif [[ $COUNTER == 12 ]] ; then
       echo "$COUNTER_12" ; sleep 1
    elif [[ $COUNTER == 13 ]] ; then
       echo "$COUNTER_13" ; sleep 1
    fi
    let COUNTER=COUNTER+1
done

# Begin install
DIST=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^DIST/{v=t($2)};END{printf "%s\n",v}' $CUR_DIR/env) && INST=$(sudo tar zxvf $DIST | grep setup-*) && sudo ./$INST
sudo sed -i "s|$PATH_REP|#$PATH_REP|g" /etc/apt/sources.list | sudo sed -i "s|##$PATH_REP|#$PATH_REP|g" /etc/apt/sources.list

#############in_dev################