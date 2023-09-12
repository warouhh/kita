#!/bin/bash
run_eula() {
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1
}

run_update() {
clear
rm -fr *
DATE2=$(date -R | cut -d " " -f -5)
apt install curl -y
rm -fr setup.sh
apt install haproxy -y
apt update -y
apt install iftop -y
apt install vnstat -y
apt install -y python3 python3-dnslib net-tools
apt install -y python3 python3-pip git
pip3 install cfscrape
apt install ncurses-utils -y
apt install dnsutils -y
apt install golang -y
apt install git -y
apt install curl -y
apt install wget -y
apt install ncurses-utils -y
apt install screen -y
apt install cron -y
apt install iptables -y
apt install -y git screen whois dropbear wget
apt install -y pwgen python php jq curl
apt install -y sudo gnutls-bin
apt install -y mlocate dh-make libaudit-dev build-essential
apt install -y libjpeg-dev zlib1g-dev libpng-dev
pip3 install pillow
apt install -y dos2unix debconf-utils
service cron reload
apt install python ruby -y
gem install lolcat
service cron restart
apt install ruby -y
gem install lolcat
apt install zip -y
apt install unzip -y
cd
}

run_info() {
curl ipinfo.io/org > /root/.isp
curl ipinfo.io/city > /etc/xray/city
curl ipinfo.io/org > /root/.myisp
curl ipinfo.io/city > /root/.city
curl ipinfo.io/city > /root/.mycity
curl ifconfig.me > /root/.ip
curl ipinfo.io/region > /root/.region
curl ifconfig.me > /root/.myip
clear
}

run_folder() {
mkdir /etc/slowdns
mkdir /etc/xray
mkdir /etc/websocket
mkdir /etc/xray
mkdir /etc/funny
mkdir /etc/funny/trojan
mkdir /etc/funny/vless
mkdir /etc/funny/vmess
mkdir /etc/funny/limit
mkdir /etc/funny/socks5
mkdir /etc/funny/limit/trojan
mkdir /etc/funny/limit/vless
mkdir /etc/funny/limit/vmess
mkdir /etc/funny/limit/ssh
mkdir /etc/funny/limit/sosck5
mkdir /etc/funny/limit/socks5/ip
mkdir /etc/funny/limit/socks5/quota
mkdir /etc/funny/limit/ssh/ip
mkdir /etc/funny/limit/trojan/ip
mkdir /etc/funny/limit/trojan/quota
mkdir /etc/funny/limit/vless/ip
mkdir /etc/funny/limit/vless/quota
mkdir /etc/funny/limit/vmess/ip
mkdir /etc/funny/limit/vmess/quota
mkdir /etc/funny/log
mkdir /etc/funny/log/trojan
mkdir /etc/funny/log/vless
mkdir /etc/funny/log/vmess
mkdir /etc/funny/log/ssh
mkdir /etc/funny/log/socks5
mkdir /etc/funny/cache
mkdir /etc/funny/cache/trojan-tcp
mkdir /etc/funny/cache/trojan-ws
mkdir /etc/funny/cache/trojan-grpc
mkdir /etc/funny/cache/vless-ws
mkdir /etc/funny/cache/vless-grpc
mkdir /etc/funny/cache/vmess-ws
mkdir /etc/funny/cache/vmess-grpc
mkdir /etc/funny/cache/vmess-ws-orbit
mkdir /etc/funny/cache/vmess-ws-orbit1
mkdir /etc/funny/cache/socks5
touch /root/.system
touch /root/.log-limit
touch /root/.log-limit.txt
touch /root/.log-install.txt
}

run_gotop() {
# > install gotop
gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
# Mendapatkan informasi OS
OS=$(lsb_release -si)

# Periksa jika OS adalah Ubuntu 20.04
if [ "$OS" = "Ubuntu" ]; then
    VERSION=$(lsb_release -sr)
    if [ "$VERSION" = "20.04" ]; then
        echo "Menggunakan snap untuk instalasi gotop di Ubuntu 20.04"
        snap install gotop
    else
        echo "Versi Ubuntu yang berbeda. Anda perlu menginstal gotop secara manual."
    fi
else
    echo "Bukan Ubuntu. Menggunakan apt untuk instalasi gotop."
curl -sL "$gotop_link" -o /tmp/gotop.deb
dpkg -i /tmp/gotop.deb >/dev/null 2>&1
fi
}

run_izin() {
  # Link izin IP VPS
  url_izin='https://raw.githubusercontent.com/Rerechan02/iziznscript/main/ip'

  # Mendapatkan IP VPS saat ini
  ip_vps=$(curl -s ifconfig.me)

  # Mendapatkan isi file izin.txt dari URL
  izin=$(curl -s "$url_izin")

  # Memeriksa apakah konten izin.txt berhasil didapatkan
  if [[ -n "$izin" ]]; then
    while IFS= read -r line; do
      # Memisahkan nama VPS, IP VPS, dan tanggal kadaluwarsa
      nama=$(echo "$line" | awk '{print $1}')
      ipvps=$(echo "$line" | awk '{print $2}')
      tanggal=$(echo "$line" | awk '{print $3}')

      # Memeriksa apakah IP VPS saat ini cocok dengan IP VPS yang ada di izin.txt
      if [[ "$ipvps" == "$ip_vps" ]]; then
        echo "Nama VPS: $nama"
        echo "IP VPS: $ipvps"
        echo "Tanggal Kadaluwarsa: $tanggal"
        break
      fi
    done <<< "$izin"

    # Memeriksa apakah IP VPS ditemukan dalam izin.txt
    if [[ "$ipvps" != "$ip_vps" ]]; then
      # Add your message here for when the VPS doesn't have permission
clear
      echo -e "\e[33m ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m" | lolcat
      echo -e "                 • FunnyVpn •                 "
      echo -e "\e[33m ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m" | lolcat
      echo -e ""
      echo -e "\e[93m Nama\e[32;1m   : $nama "
      echo -e "\e[93m IP VPS\e[32;1m : $ip_vps"
      echo -e "\e[93m Domain\e[32;1m : $(cat /etc/xray/domain)"
      echo -e ""
      echo -e "\e[93m Ssh\e[32;1m    : STOPPED "
      echo -e "\e[93m Trojan\e[32;1m : STOPPED "
      echo -e "\e[93m Vless\e[32;1m  : STOPPED "
      echo -e "\e[93m Vmess\e[32;1m  : STOPPED "
      echo -e ""        
      echo -e "${red} VPS Anda Tidak Izinkan \e[32;1m "
      echo -e "${red} Contact Admin Untuk Perizinan \e[32;1m" | lolcat
      echo -e ""
      echo -e "\e[93m Telegram\e[32;1m : https://t.me/Funy_vpn"
      echo -e "\e[33m ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m" | lolcat
      echo -e ""
      exit 0
    fi
  else
    echo "Konten izin.txt tidak berhasil didapatkan dari URL"
    exit 0
  fi
  clear
}

run_ayaka() {
clear
if [[ -e /etc/debian_version ]]; then
	source /etc/os-release
	OS=$ID # debian or ubuntu
elif [[ -e /etc/centos-release ]]; then
	source /etc/os-release
	OS=centos
fi
sudo apt install netfilter-persistent -y
sudo apt-get remove --purge ufw firewalld -y 
sudo apt-get remove --purge exim4 -y 
sudo apt install -y screen curl jq bzip2 gzip coreutils rsyslog iftop \
 htop zip unzip net-tools sed gnupg gnupg1 \
 bc sudo apt-transport-https build-essential dirmngr libxml-parser-perl neofetch screenfetch git lsof \
 openssl openvpn easy-rsa fail2ban tmux \
 stunnel4 vnstat squid3 \
 dropbear  libsqlite3-dev \
 socat cron bash-completion ntpdate xz-utils sudo apt-transport-https \
 gnupg2 dnsutils lsb-release chrony
curl -sSL https://deb.nodesource.com/setup_16.x | bash - 
sudo apt-get install nodejs -y
/etc/init.d/vnstat restart
wget -q https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc >/dev/null 2>&1 && make >/dev/null 2>&1 && make install >/dev/null 2>&1
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
rm -f /root/vnstat-2.6.tar.gz >/dev/null 2>&1
rm -rf /root/vnstat-2.6 >/dev/null 2>&1
sudo apt install -y libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev xl2tpd pptpd
sleep 1
clear
}

run_domain() {
read -p "Input Your SubDomain : " domain
read -p "Input Your NS Domain : " nsdomain
echo "$domain" > /root/scdomain
echo "$domain" > /etc/xray/scdomain
echo "$domain" > /etc/xray/domain
echo "$domain" > /etc/v2ray/domain
echo "$domain" > /root/domain
echo "$nsdomain" > /etc/slowdns/nsdomain
echo "$nsdomain" > /etc/xray/dns
echo "$nsdomain" > /etc/xray/nsdomain
echo "$nsdomain" > /etc/v2ray/dns
echo "IP=$domain" > /var/lib/ipvps.conf
clear
wget -O dnstt-server "https://raw.githubusercontent.com/Rerechan02/v/main/wireguard/dnstt-server" >/dev/null 2>&1
chmod +x dnstt-server >/dev/null 2>&1
wget -O dnstt-client "https://raw.githubusercontent.com/Rerechan02/v/main/wireguard/dnstt-client" >/dev/null 2>&1
chmod +x dnstt-client >/dev/null 2>&1
./dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
chmod +x *
mv * /etc/slowdns
wget -O /etc/systemd/system/client.service "https://raw.githubusercontent.com/Rerechan02/v/main/wireguard/client" >/dev/null 2>&1
wget -O /etc/systemd/system/server.service "https://raw.githubusercontent.com/Rerechan02/v/main/wireguard/server" >/dev/null 2>&1
sed -i "s/xxxx/$nsdomain/g" /etc/systemd/system/client.service 
sed -i "s/xxxx/$nsdomain/g" /etc/systemd/system/server.service
systemctl daemon-reload
systemctl enable server
systemctl enable client
systemctl restart client
sydtemctl restart server
}

run_ip() {
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 80 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 443 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 8080 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 8080 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 2082 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 2082 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 2096 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 2096 -j ACCEPT
}

run_tatang() {
cd
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 3303' /etc/ssh/sshd_config
/etc/init.d/ssh restart
apt install dropbear -y
rm /etc/default/dropbear
rm /etc/issue.net
cat>  /etc/default/dropbear << END
# disabled because OpenSSH is installed
# change to NO_START=0 to enable Dropbear
NO_START=0
# the TCP port that Dropbear listens on
DROPBEAR_PORT=111
DROPBEAR_PORT=143

# any additional arguments for Dropbear
DROPBEAR_EXTRA_ARGS="-p 109 -p 69 "

# specify an optional banner file containing a message to be
# sent to clients before they connect, such as "/etc/issue.net"
DROPBEAR_BANNER="/etc/issue.net"

# RSA hostkey file (default: /etc/dropbear/dropbear_rsa_host_key)
#DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"

# DSS hostkey file (default: /etc/dropbear/dropbear_dss_host_key)
#DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"

# ECDSA hostkey file (default: /etc/dropbear/dropbear_ecdsa_host_key)
#DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"

# Receive window size - this is a tradeoff between memory and
# network performance
DROPBEAR_RECEIVE_WINDOW=65536
END
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
rm -fr /etc/issue.net
cat> /etc/issue.net << END
<p style="text-align:center"><b>
<br><font color='#FFCCFF'><b>╔══════════ 🌦🌦🌦 ══════════╗</b></font>
<br><font color='#FF99FF'><b>⇱ CLOUDVPN TUNNEL ⇲</b></font>
<br><font color='#FF66FF'><b>╚══════════ 🌦🌦🌦 ══════════╝</b><br></font>
<br><font color='#FF00FF'><b>╔══════════ 🌦🌦🌦 ══════════╗</b></font>
<br><font color='#FF0099'><b>No DDOS - No Torrent - No Porno - No OverDownload</b></font>
<br><font color='#990066'><b>No Carding - No Hacking - No Multi Login - No Spamming</b></font>
<br><font color='#660066'><b>No Bot - No Mining - No Ilegal Activities</b></font>
<br><font color='#330066'><b>╚══════════ 🌦🌦🌦 ══════════╝</b><br></font>
<br><font color='#660099'>&ensp;⇱ Melanggar Banned ⇲</font>
<br><font color='#663399'>&ensp;⇱ MAX 01 DEVICE ⇲</font>
<br><font color='#663399'>&ensp;⇱ Happy Use ⇲</font>
<br><font color='#9900CC'><b>╔══════════ 🌦🌦🌦 ══════════╗</b></font>              
<br><font color='#9933FF'><b>⇱ Contact Owner ⇲</b></font>
<br><font color='#9966FF'><b>GROUP : https://t.me/vpnawan </b></font>
<br><font color='#9999FF'><b>t.me/amiqyu</b></font>
<br><font color='#CCCCFF'><b>╚══════════ 🌦🌦🌦 ══════════╝</b><br>
END
/etc/init.d/dropbear restart
}

run_cantikva() {
if [ -d '/usr/local/ddos' ]; then
	echo; echo; echo "Please un-install the previous version first"
	exit 0
else
	mkdir /usr/local/ddos
fi
clear
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
}

run_tor() {
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload
}

run_butuh() {
wget https://raw.githubusercontent.com/Rerechan02/UDP/main/udp.sh && chmod +x udp.sh && ./udp.sh
dd if=/dev/zero of=/swapfile bs=1024 count=1048576
mkswap /swapfile
chown root:root /swapfile
chmod 0600 /swapfile >/dev/null 2>&1
swapon /swapfile >/dev/null 2>&1
sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab
}

run_ssh() {
#!/bin/bash
apt dist-upgrade -y
apt install netfilter-persistent -y
apt-get remove --purge ufw firewalld -y
apt install -y screen curl jq bzip2 gzip vnstat coreutils rsyslog iftop zip unzip git apt-transport-https build-essential -y
export DEBIAN_FRONTEND=noninteractive
MYIP=$(wget -qO- ipinfo.io/ip);
MYIP2="s/xxxxxxxxx/$MYIP/g";
NET=$(ip -o $ANU -4 route show to default | awk '{print $5}');
source /etc/os-release
ver=$VERSION_ID
country=ID
state=Indonesia
locality=Jakarta
organization=none
organizationalunit=none
commonname=none
email=none
curl -sS https://github.com/Rerechan02/v/raw/main/ssh/password | openssl aes-256-cbc -d -a -pass pass:scvps07gg -pbkdf2 > /etc/pam.d/common-password
chmod +x /etc/pam.d/common-password
cd
# Edit file /etc/systemd/system/rc-local.service
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END
# nano /etc/rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END
# Ubah izin akses
chmod +x /etc/rc.local
# enable rc local
systemctl enable rc-local
systemctl start rc-local.service
#update
apt update -y
apt upgrade -y
apt dist-upgrade -y
apt-get remove --purge ufw firewalld -y
apt-get remove --purge exim4 -y
#install jq
apt -y install jq
#install shc
apt -y install shc
# install wget and curl
apt -y install wget curl
#figlet
apt-get install figlet -y
apt-get install ruby -y
gem install lolcat
# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
install_ssl(){
    if [ -f "/usr/bin/apt-get" ];then
            isDebian=`cat /etc/issue|grep Debian`
            if [ "$isDebian" != "" ];then
                    apt-get install -y nginx certbot
                    apt install -y nginx certbot
                    sleep 3s
            else
                    apt-get install -y nginx certbot
                    apt install -y nginx certbot
                    sleep 3s
            fi
    else
        yum install -y nginx certbot
        sleep 3s
    fi

    systemctl stop nginx.service

    if [ -f "/usr/bin/apt-get" ];then
            isDebian=`cat /etc/issue|grep Debian`
            if [ "$isDebian" != "" ];then
                    echo "A" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain
                    sleep 3s
            else
                    echo "A" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain
                    sleep 3s
            fi
    else
        echo "Y" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain
        sleep 3s
    fi
}

# install webserver
apt -y install nginx
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
mkdir -p /home/vps/public_html
mkdir -p /var/www/html
/etc/init.d/nginx restart
cd
# make a certificate
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem
# install fail2ban
apt -y install fail2ban
cd
clear
apt autoclean -y >/dev/null 2>&1
if dpkg -s unscd >/dev/null 2>&1; then
apt -y remove --purge unscd >/dev/null 2>&1
fi
apt-get -y --purge remove samba* >/dev/null 2>&1
apt-get -y --purge remove apache2* >/dev/null 2>&1
apt-get -y --purge remove bind9* >/dev/null 2>&1
apt-get -y remove sendmail* >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1
cd
chown -R www-data:www-data /home/vps/public_html
chown -R www-data:www-data /var/www/html
/etc/init.d/nginx restart >/dev/null 2>&1
/etc/init.d/openvpn restart >/dev/null 2>&1
/etc/init.d/ssh restart >/dev/null 2>&1
/etc/init.d/dropbear restart >/dev/null 2>&1
/etc/init.d/fail2ban restart >/dev/null 2>&1
/etc/init.d/stunnel4 restart >/dev/null 2>&1
/etc/init.d/vnstat restart >/dev/null 2>&1
history -c
echo "unset HISTFILE" >> /etc/profile
rm -f /root/key.pem
rm -f /root/cert.pem
rm -f /root/ssh-vpn.sh
rm -f /root/bbr.sh
clear
}

run_xray() {
#!/bin/bash
wget https://github.com/NevermoreSSH/VVV/raw/main/badvpn/setup.sh && chmod +x * && ./setup.sh
rm -fr setup.sh
clear
domain=$(cat /etc/xray/domain)
apt install iptables iptables-persistent -y
ntpdate pool.ntp.org 
timedatectl set-ntp true
systemctl enable chronyd
systemctl restart chronyd
systemctl enable chrony
systemctl restart chrony
chronyc sourcestats -v
chronyc tracking -v
apt clean all && apt update
apt install curl socat xz-utils wget apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release -y 
apt install socat cron bash-completion ntpdate -y
ntpdate pool.ntp.org
apt -y install chrony
apt install zip -y
apt install curl pwgen openssl netcat cron -y
domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
chown www-data.www-data $domainSock_dir
mkdir -p /var/log/xray
mkdir -p /etc/xray
chown www-data.www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
touch /var/log/xray/access2.log
touch /var/log/xray/error2.log
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 1.7.2
systemctl stop nginx
mkdir /root/.acme.sh
curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
# nginx renew ssl
echo -n '#!/bin/bash
/etc/init.d/nginx stop
"/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" &> /root/renew_ssl.log
/etc/init.d/nginx start
/etc/init.d/nginx status
' > /usr/local/bin/ssl_renew.sh
chmod +x /usr/local/bin/ssl_renew.sh
if ! grep -q 'ssl_renew.sh' /var/spool/cron/crontabs/root;then (crontab -l;echo "15 03 */3 * * /usr/local/bin/ssl_renew.sh") | crontab;fi
mkdir -p /home/vps/public_html
wget -O /etc/xray/config.json https://raw.githubusercontent.com/Rerechan02/1.0/main/config.json
wget -O /etc/nginx/conf.d/funny.conf https://raw.githubusercontent.com/Rerechan02/1.0/main/funny.conf
rm -rf /etc/systemd/system/xray.service.d
rm -rf /etc/systemd/system/xray@.service
cat <<EOF> /etc/systemd/system/xray.service
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

EOF
cat > /etc/systemd/system/runn.service <<EOF
[Unit]
Description=Mantap-Sayang
After=network.target

[Service]
Type=simple
ExecStartPre=-/usr/bin/mkdir -p /var/run/xray
ExecStart=/usr/bin/chown www-data:www-data /var/run/xray
Restart=on-abort

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/nginx/nginx.conf <<NLOK
user www-data;
worker_processes 1;
pid /var/run/nginx.pid;
events {
	multi_accept on;
	worker_connections 1024;
}
http {
	gzip on;
	gzip_vary on;
	gzip_comp_level 5;
	gzip_types text/plain application/x-javascript text/xml text/css;
	autoindex on;
	sendfile on;
	tcp_nopush on;
	tcp_nodelay on;
	keepalive_timeout 65;
	types_hash_max_size 2048;
	server_tokens off;
	include /etc/nginx/mime.types;
	default_type application/octet-stream;
	access_log /var/log/nginx/access.log;
	error_log /var/log/nginx/error.log;
	client_max_body_size 32M;
	client_header_buffer_size 8m;
	large_client_header_buffers 8 8m;
	fastcgi_buffer_size 8m;
	fastcgi_buffers 8 8m;
	fastcgi_read_timeout 600;
	#CloudFlare IPv4
	set_real_ip_from 199.27.128.0/21;
	set_real_ip_from 173.245.48.0/20;
	set_real_ip_from 103.21.244.0/22;
	set_real_ip_from 103.22.200.0/22;
	set_real_ip_from 103.31.4.0/22;
	set_real_ip_from 141.101.64.0/18;
	set_real_ip_from 108.162.192.0/18;
	set_real_ip_from 190.93.240.0/20;
	set_real_ip_from 188.114.96.0/20;
	set_real_ip_from 197.234.240.0/22;
	set_real_ip_from 198.41.128.0/17;
	set_real_ip_from 162.158.0.0/15;
	set_real_ip_from 104.16.0.0/12;
	#Incapsula
	set_real_ip_from 199.83.128.0/21;
	set_real_ip_from 198.143.32.0/19;
	set_real_ip_from 149.126.72.0/21;
	set_real_ip_from 103.28.248.0/22;
	set_real_ip_from 45.64.64.0/22;
	set_real_ip_from 185.11.124.0/22;
	set_real_ip_from 192.230.64.0/18;
	real_ip_header CF-Connecting-IP;
	include /etc/nginx/conf.d/*.conf;
}
NLOK
#restart
mv /root/domain /etc/xray/ 
if [ -f /root/scdomain ];then
rm /root/scdomain > /dev/null 2>&1
fi
clear
}

run_ws() {
rm -fr /etc/haproxy/haproxy.cfg
cat >/etc/haproxy/haproxy.cfg <<HAH
global
    daemon
    maxconn 256

defaults
    mode tcp
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend ssh-ssl
    bind *:443 ssl crt /etc/haproxy/funny.pem
    mode tcp
    option tcplog
    default_backend ssh-backend

backend ssh-backend
    mode tcp
    option tcplog
    server ssh-server 127.0.0.1:22
HAH
cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/funny.pem
#wevsocket
cd /usr/local/bin
wget https://raw.githubusercontent.com/Rerechan02/1.0/main/ws.zip
unzip ws.zip
rm -fr ws.zip
chmod +x *
#service
cd /etc/systemd/system
wget https://raw.githubusercontent.com/Rerechan02/1.0/main/service.zip
unzip service.zip
rm -fr service.zip
# MENU
cd /usr/bin
rm -fr menu
rm -fr /usr/bin/menu
wget https://raw.githubusercontent.com/Rerechan02/1.0/main/funny.zip
unzip funny.zip
rm -fr funny.zip
chmod +x *
clear
}

run_limit() {
#kwowo
cat> /etc/systemd/system/quota.service << END
[Unit]
Description=Checker Service

[Service]
Type=simple
Restart=always
ExecStart=/usr/bin/quota

[Install]
WantedBy=multi-user.target
END
sed -i "s/xxx/$domain/g" /etc/nginx/conf.d/funny.conf
systemctl daemon-reload
systemctl restart haproxy
systemctl enable ws-stunnel
systemctl enable ws-dropbear
systemctl enable quota
systemctl restart quota
systemctl restart ws-stunnel
systemctl restart ws-dropbear
systemctl enable xray
systemctl restart xray
systemctl restart nginx
systemctl enable runn
systemctl restart runn
}

run_ayaya() {
echo "funny" >> /root/.profile
rm /root/setup.sh >/dev/null 2>&1
rm /root/ins-xray.sh >/dev/null 2>&1
rm /root/insshws.sh >/dev/null 2>&1
rm -fr /root/*
clear
echo "*/15 * * * * root limit" >> /etc/crontab
echo "*/1 * * * root xp" >> /etc/crontab
echo "0 0 * * * root reboot" >> /etc/crontab
echo "UQ3w2q98BItd3DPgyctdoJw4cqQFmY59ppiDQdqMKbw=" > /etc/xray/serverpsk
touch /root/.system
touch /etc/trojan/.trojan.db
touch /etc/vless/.vless.db
touch /etc/vmess/.vmess.db
rm -fr /root/.bash_history
}

run_xiangling() {
export CHATID="6389176425"
export KEY="6230907878:AAExag4j8lRsJbMdAIv6T9STI1g6kp_Vq68"
export TIME="10"
export URL="https://api.telegram.org/bot$KEY/sendMessage"
clear
echo -e ""
TEXT="
Detail Install Script
==================================
IP VPS: $ip_vps
Domain: $(cat /etc/xray/domain)
Waktu Install: $DATE2
Client Name: $nama
Expired: $tanggal
==================================
"
clear
curl -s --max-time $TIME -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
clear
echo -e "
Detail Install Script
==================================
IP VPS        : $ip_vps
Domain        : $(cat /etc/xray/domain)
Date & Time   : $DATE2
Client Name   : $nama
Expired       : $tanggal
==================================
     <= Wajib di baca & lakukan =>
==================================
Port login VPS dari 22 di ganti ke 3303
karna kalo login vps make port 22 gamoang kena brute force
Untuk membuka panel AutoSC Masukan
perintah ( funny ) tanpa tanda kurung
==================================
"
read -p "Pres enter untuk reboot : " ieieie
touch /root/system
reboot
}

run_xiangling_istri_gw() {
run_eula
run_update
run_ayaka
run_folder
run_info
run_gotop
run_izin
run_domain
run_ssh
run_xray
run_tatang
run_ip
run_cantikva
run_tor
run_butuh
run_ws
run_limit
run_ayaya
run_xiangling
}

run_xiangling_istri_gw
