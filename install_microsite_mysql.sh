#!/bin/bash

echo "This script installs the server as Microsite. See details here:"
echo "https://atlassian.ebcont-et.com/confluence/display/ITI/Microsite+-+Setup"
echo "This script must run as ROOT"
echo "You can run it something like this to also have logs"
echo "/root/bin/install-microsite.sh 2>&1 | tee /var/log/install-microsite.log"
echo "This script works best on Ubuntu 12.04"
echo "Setup will begin now - if you want to skip Ctrl+C"
sleep 15
echo "Before we can begin, we need some information"
echo "#######################"
echo "Please enter the domain-name, for which Apache and Liferay will be configured (eg www.mysite.com)"
echo -n "Domain: "
read xdomain
echo "Please enter a password, which should be used for root-access of the mysql-database"
echo -n "Mysql-Password: "
read xmysqlpwd
echo "Please enter your email-adress - we will send an email to you for testing the email-settings"
echo -n "Your Email-Adress: "
read xemail
echo "Please enter your local IP-address - we will allow ssh-connections from this IP-address (eg 194.166.221.74)"
echo -n "Your IP: "
read xipaddress
echo "Please enter your Gmail-Username for sending mails (eg firstname.lastname@ebcont.com)"
echo -n "Gmail SMTP-Username: "
read xemailusername
echo "Please enter your Gmail-Password for sending mails"
echo -n "Gmail-Password: "
read xemailpassword
echo "Now please enter the password to access Awstats with user awstats under http://$xdomain/awstats"
echo -n "Awstats-Password: "
read xawstatspassword
echo "#######################"
echo "Thank you for input"
echo "Installation begins in 10 seconds - this is your last chance to cancel"
echo "Installation will need about 10 minutes - there is no more input necessary- if you don't see HAVE FUN as the last line of the installation, something went wrong. Then you have to start installation again."
sleep 5

echo "edit basics"
cat << EOF >> /root/.bashrc
#added by script install_microsite_mysql.sh
alias dir='ls -lha'
alias msg='tail -f /var/log/messages'
alias ..='cd ..'
alias ...='cd ../..'
alias qdu='du -h --max-depth=1'
alias qifc='ifconfig | grep -B2 "inet addr"'
EOF

echo "do OS updates"
apt-get -y update
apt-get -y upgrade

echo "install vim"
apt-get -y install vim

echo "install unzip - needed later"
apt-get -y install unzip

echo "install chkconfig - who can work without it?"
apt-get -y install chkconfig

echo "install and configure shorewall"
apt-get -y install shorewall
cp /usr/share/doc/shorewall/examples/one-interface/* /etc/shorewall/
sed -i "s/startup=0/startup=1/g" /etc/default/shorewall
cp /etc/shorewall/rules /etc/shorewall/rules.orig
sed -i "s/Ping(DROP)/Ping(ACCEPT)/g" /etc/shorewall/rules
cat << EOF >> /etc/shorewall/rules
#added by script install_microsites.sh
# MAINTENANCE
 
# ECBONT Office
ACCEPT          net:188.21.79.96/29     \$FW     tcp     ssh
ACCEPT          net:62.116.82.210/28    \$FW     tcp     ssh
 
# ADE Home
ACCEPT          net:86.59.126.136/29    \$FW     tcp     ssh
# internal
ACCEPT        net:10.0.2.0/24    \$FW    tcp        ssh
ACCEPT        net:$xipaddress        \$FW    tcp        ssh
 
# INTERNAL TESTING
#ACCEPT          net:188.21.79.96/29     \$FW     tcp     www
#ACCEPT          net:86.59.126.136/29    \$FW     tcp     www
 
# PUBLIC RULES PORT 80
ACCEPT          net     \$FW     tcp     www
EOF
service shorewall restart

echo "Install Sun JDK v1.7"
#oracle wants you to accept license agreement - so we use cookies :-)
mkdir -p /root/install
wget -P /root/install --no-cookies --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2Ftechnetwork%2Fjava%2Fjavase%2Fdownloads%2Fjdk-7u3-download-1501626.html;" "http://download.oracle.com/otn-pub/java/jdk/7u45-b18/jdk-7u45-linux-x64.tar.gz"
tar xfvz /root/install/jdk-7u45-linux-x64.tar.gz -C /opt/
ln -s /opt/jdk1.7.0_45/ /opt/java
update-alternatives --install "/usr/bin/java" "java" "/opt/java/bin/java" 1
export JAVA_HOME=/opt/java
export JRE_HOME=$JAVA_HOME/jre
export PATH=$PATH:$JAVA_HOME/bin
cat << EOF >> /etc/profile
#added by script install_microsites_mysql.sh
export JAVA_HOME=/opt/java
export JRE_HOME=\$JAVA_HOME/jre
export PATH=\$PATH:\$JAVA_HOME/bin
EOF

echo "Install Mysql"
#this is needed to NOT prompt the root-pwd while installing
echo mysql-server-5.5 mysql-server/root_password password $xmysqlpwd | debconf-set-selections
echo mysql-server-5.5 mysql-server/root_password_again password $xmysqlpwd | debconf-set-selections
apt-get -y install mysql-server

echo "Install Apache2"
apt-get -y install apache2
a2enmod proxy
a2enmod proxy_http
a2enmod auth_digest
a2enmod auth_basic

echo "Setup admin-networks.conf"
cat << EOF > /etc/apache2/admin-networks.conf
Order allow,deny

# EBCONT ET office IP range
Allow from 188.21.79.96/29
Allow from 62.116.82.210/28

# Thieme Net
Allow from 91.208.107.0/24
Allow from 91.208.107.57
Allow from 91.208.107.58
Allow from 91.208.107.59
Allow from 91.208.107.60
Allow from 91.208.107.61

# Thieme New York
Allow from 38.98.125.2

# AHE Home
Allow from 86.59.126.136/29

# ADE Home
Allow from 86.59.126.139

# IP internal and Installation
Allow from 192.168.56.0/24
Allow from $xipaddress
EOF

echo "Configure Apache2"
cp /etc/apache2/sites-available/default /etc/apache2/sites-available/default.orig
cat << EOF > /etc/apache2/sites-available/$xdomain

<VirtualHost *:80>
        NameVirtualHost $xdomain:80
        ServerAdmin webmaster@$xdomain
 
        DocumentRoot /var/www
        <Directory />
                Options FollowSymLinks
                AllowOverride None
        </Directory>
        <Directory /var/www/>
                Options Indexes FollowSymLinks MultiViews
                AllowOverride None
                Order allow,deny
                allow from all
        </Directory>
 
        ErrorLog /var/log/apache2/$xdomain-error.log
 
        # Possible values include: debug, info, notice, warn, error, crit,
        # alert, emerg.
        LogLevel warn
 
        CustomLog /var/log/apache2/$xdomain-access.log combined
 
        # Reverse Proxy Configuration
        <Proxy *>
                Order deny,allow
                Allow from all
        </Proxy>
 
        # Exclude awstats - has to be first
        ProxyPass /awstats !
        ProxyPass /awstatsclasses !
        ProxyPass /awstats-icon !
        ProxyPass /awstats-css !
 
        # Pass all other requests to tomcat
        ProxyPass / http://127.0.0.1:8080/
        ProxyPassReverse / http://127.0.0.1:8080/
 
        #do a basic authentication
        #<Location />
        #       AuthType Basic
        #       AuthName "Site"
        #       AuthUserFile /etc/apache2/auth/site-basic
        #       Require valid-user
        #</Location>
                # CMS CONSOLE
 
        <Location /adminadmin>
        Include /etc/apache2/admin-networks.conf
        </Location>
 
        <Location /2>
        Include /etc/apache2/admin-networks.conf
        </Location>
 
        <Location /c/portal/login>
        Include /etc/apache2/admin-networks.conf
        </Location>
 
        <Location /web/guest/adminadmin>
        Include /etc/apache2/admin-networks.conf
        </Location>
 
        <Location /web/guest/2>
        Include /etc/apache2/admin-networks.conf
        </Location>
 
 
        # AWSTATS
        Alias /awstatsclasses "/usr/share/awstats/lib/"
        Alias /awstats-icon/ "/usr/share/awstats/icon/"
        Alias /awstatscss "/usr/share/doc/awstats/examples/css"
 
        ScriptAlias /awstats /usr/lib/cgi-bin/
        <Directory "/usr/lib/cgi-bin">
                AllowOverride None
                Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch
                Order allow,deny
                Allow from all
        </Directory>
 
        <LocationMatch "/awstats*">
                AuthType Digest
                AuthName "awstats"
                AuthUserFile /etc/apache2/auth/stats-digest
                Require valid-user
                Include /etc/apache2/admin-networks.conf
         </LocationMatch>
 
</VirtualHost>

EOF

cat << EOF >> /etc/apache2/apache2.conf
#added by script install_microsites_mysql.sh
ServerSignature Off
ServerTokens Prod
EOF
ln -s /etc/apache2/sites-available/$xdomain /etc/apache2/sites-enabled/
rm /etc/apache2/sites-enabled/000-default
service apache2 restart

echo "Setup mod_security"
apt-get -y install libapache-mod-security
cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
a2enmod mod-security
service apache2 restart

echo "Install SMTP and postfix for using gmail"
export DEBIAN_FRONTEND=noninteractive
apt-get -y install postfix
sed -i "s/inet_interfaces/#inet_interfaces/g" /etc/postfix/main.cf
sed -i "s/relayhost/#relayhost/g" /etc/postfix/main.cf
cat << EOF >> /etc/postfix/main.cf
##### client TLS parameters #####
smtp_tls_loglevel=1
smtp_tls_security_level=encrypt
smtp_sasl_auth_enable=yes
smtp_sasl_password_maps=hash:/etc/postfix/sasl/passwd
smtp_sasl_security_options = noanonymous
inet_interfaces = loopback-only
relayhost = [smtp.gmail.com]:587
EOF
mkdir -p /etc/postfix/sasl
echo "[smtp.gmail.com]:587 $xemailusername:$xemailpassword" > /etc/postfix/sasl/passwd
postmap /etc/postfix/sasl/passwd
chown root.root /etc/postfix/sasl/*
chmod 600 /etc/postfix/sasl/*
apt-get -y install mailutils
echo "testmessage from new installed microsites-server" | mail -s "testmail from $HOSTNAME" $xemail

echo "Install AWStats"
mkdir -p /etc/apache2/auth/
(echo -n "awstats:awstats:" && echo -n "awstats:awstats:$xawstatspassword" | md5sum | awk '{print $1}' ) >> /etc/apache2/auth/stats-digest
apt-get -y install awstats
cp /etc/awstats/awstats.conf /etc/awstats/awstats.$xdomain.conf
sed -i "s#LogFile=\"/var/log/apache2/access.log\"#LogFile=\"/var/log/apache2/$xdomain-access.log\"#g" /etc/awstats/awstats.$xdomain.conf
sed -i "s#SiteDomain=\"\"#SiteDomain=\"$xdomain\"#g" /etc/awstats/awstats.$xdomain.conf
cat << EOF >> /etc/crontab
#was added by script install_microsite.sh
0 0 * * *    root    /usr/lib/cgi-bin/awstats.pl -config=$xdomain -update
EOF
service cron restart
service apache2 restart

echo "Install liferay"
wget -P /root/install "http://optimate.dl.sourceforge.net/project/lportal/Liferay%20Portal/6.2.0%20GA1/liferay-portal-tomcat-6.2.0-ce-ga1-20131101192857659.zip"
unzip -d /opt/ /root/install/liferay-portal-tomcat-6.2.0-ce-ga1-20131101192857659.zip
ln -s /opt/liferay-portal-6.2.0-ce-ga1/ /opt/liferay
ln -s /opt/liferay/tomcat-7.0.42/logs/catalina.out /var/log/tomcat.log
cat << EOF > /opt/liferay/tomcat-7.0.42/webapps/ROOT/WEB-INF/classes/portal-ext.properties
jdbc.default.driverClassName=com.mysql.jdbc.Driver
jdbc.default.url=jdbc:mysql://localhost/lportal?useUnicode=true&characterEncoding=UTF-8&useFastDateParsing=false
jdbc.default.username=root
jdbc.default.password=$xmysqlpwd
schema.run.enabled=true
schema.run.minimal=true
web.server.host=$xdomain
web.server.protocol=http
web.server.http.port=80
EOF
mysql -uroot -p$xmysqlpwd -e "create database lportal"

echo "Creating startup-script and user"
adduser --shell /bin/bash --disabled-password --no-create-home --home /opt/liferay/ --gecos "Liferay,,," liferay
chown liferay.liferay /opt/liferay/ -R
chown liferay.liferay /opt/liferay -R
mkdir -p /var/run/liferay
chmod 777 /var/run/liferay -R
touch /etc/init.d/liferay
chmod u+x /etc/init.d/liferay
update-rc.d liferay defaults
cat << EOF > /etc/init.d/liferay
#!/bin/bash
### BEGIN INIT INFO
# Provides:          liferay
# Required-Start:    \$local_fs \$remote_fs \$network
# Required-Stop:     \$local_fs \$remote_fs \$network
# Should-Start:      \$named
# Should-Stop:       \$named
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Liferay portal daemon.
# Description:       Starts the Liferay portal.
# Author:            Julien Rialland <julien.rialland@gmail.com>
### END INIT INFO
 
#Display name of the application
APP_NAME="Liferay 6.2.0"
 
#Location of Liferay installation
export LIFERAY_HOME=/opt/liferay

#unprivileged user that runs the daemon. The group/user should have been created separately,
#using groupadd/useradd
USER=liferay
GROUP=liferay
 
###This is end of the configurable section for most cases, other variable definitions follow :
 
#Only root user may run this script
if [ \`id -u\` -ne 0 ]; then
    echo "You need root privileges to run this script"
    exit 1
fi
 
#tomcat directory
#detection of the tomcat directory within liferay
TOMCAT_DIR=\`ls "\$LIFERAY_HOME" | grep tomcat | head -1\`
export CATALINA_HOME="\$LIFERAY_HOME/\$TOMCAT_DIR"
 
#location of pid file
export CATALINA_PID=/var/run/liferay/liferay.pid
 
# guess where is JAVA_HOME if needed (when then environment variable is not defined)
JVM_DIRS="/usr/lib/jvm/java-6-openjdk /usr/lib/jvm/java-6-sun /usr/lib/jvm/default-java /usr/lib/jvm/java-1.5.0-sun /usr/usr/lib/j2sdk1.5-sun /usr/lib/j2sdk1.5-ibm"
if [ -z "\$JAVA_HOME" ]; then
        for jdir in \$JVM_DIRS; do
                if [ -r "\$jdir/bin/java" -a -z "\${JAVA_HOME}" ]; then
                        export JAVA_HOME="\$jdir"
                fi
        done
fi
 
#if JAVA_HOME is still undefined, try to get it by resolving the path to the java program
if [ -z "\$JAVA_HOME" ]; then
        javaexe=\`which java\`
        if [ ! -z "\$javaexe" ]; then
                javaexe=\`readlink -m "\$javaexe"\`
                jdir="\$javaexe/.."
                export JAVA_HOME=\`readlink -m "\$jdir"\`
        fi
fi
 
#if JAVA_HOME is still undefined, crash the script
if [ -z "\$JAVA_HOME" ]; then
    echo 'The JAVA_HOME environment variable could not be determined !'
    exit 1
fi
 
#extra jvm configuration : enable jmx
#export JAVA_OPTS="\$JAVA_OPTS -Dcom.sun.management.jmxremote.port=9999 -Dcom.sun.management.jmxremote.authenticate=false -Dcom.sun.management.jmxremote.ssl=false"
 
#extra jvm configuration : enable remote debugging
#export JAVA_OPTS="\$JAVA_OPTS -Xdebug -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=9998"
 
################################################################################
 
#verify that the user that will run the daemon exists
id "\$USER" > /dev/null 2>&1
if [ "\$?" -ne "0" ]; then
    echo "User \$user does not exist !"
    exit 1
fi
 
#load utility functions from Linux Standard Base
. /lib/lsb/init-functions
 
#starts the daemon service
function start {
        log_daemon_msg "Starting \$APP_NAME"
 
        #create work directory if non-existent
        mkdir \$CATALINA_HOME/work 2>/dev/null
 
        #clear temp directory
        rm -rf "\$CATALINA_HOME/temp/*" 2>/dev/null
        mkdir \$CATALINA_HOME/temp 2>/dev/null
 
        #fix user rights on liferay home dir
        chown -R "\$GROUP":"\$USER" "\$LIFERAY_HOME"
        chmod -R ug=rwx "\$LIFERAY_HOME"
 
        #ensure that pid file is writeable
        mkdir -p \`dirname "\$CATALINA_PID"\` 2>/dev/null
        chown -R "\$GROUP":"\$USER" \`dirname "\$CATALINA_PID"\`
        #chmod ugo=rw \`dirname "\$CATALINA_PID"\`
        chmod -R ug=rwx \`dirname "\$CATALINA_PID"\`
 
        su "\$USER" -c "\$CATALINA_HOME/bin/catalina.sh start"
    status=\$?
 
        log_end_msg \$status
        exit \$status
}
 
#stops the daemon service
function stop {
        log_daemon_msg "Stopping \$APP_NAME"
        if [ ! -f "\$CATALINA_PID" ];then
            echo "file \$CATALINA_PID is missing !"
            unset CATALINA_PID
        fi
        su "\$USER" -c "\$CATALINA_HOME/bin/catalina.sh stop 10 -force"
    status=\$?
        log_end_msg \$status
        if [ "\$status" = "0" ];then
            rm -f "\$CATALINA_PID"
        fi
        exit \$status
}
 
#restarts the daemon service
function restart {
        stop
        sleep 15s
        start
}
 
#prints service status
function status {
  if [ -f "\$CATALINA_PID" ]; then
    pid=\`cat "\$CATALINA_PID"\`
    echo "\$APP_NAME is running with pid \$pid"
    exit 0
  else
    echo "\$APP_NAME is not running (or \$CATALINA_PID is missing)"
    exit 1
  fi
}
 
case "\$1" in
    start|stop|restart|status)
        \$1
    ;;
    *)
        echo \$"Usage: \$0{start|stop|restart|status}"
        exit 1
    ;;
esac
EOF

echo "#######################"
echo "script has done"
echo "starting tomcat/liferay the first time"
echo "#######################"
/etc/init.d/liferay start
echo "#######################"
echo "now we have to wait for about 3 minutes until liferay is installed"
#while waiting we do something useful
echo "3min"
updatedb
sleep 10
echo "2min 30sec"
sleep 30
echo "2min"
sleep 30
echo "1min 30sec"
sleep 30
echo "1min"
sleep 30
echo "30sec"
sleep 30
echo "lets take a look into the logs - lets do something like this:"
echo "tail -n1 /var/log/tomcat.log"
echo "#######################"
echo "#######################"
tail -n1 /var/log/tomcat.log
echo "#######################"
echo "#######################"
echo "you have to see somehting like this above:"
echo "INFO: Server startup in 218939 ms"
sleep 10
echo "if you do not see this, liferay installation is not completed yet. wait some more seconds"
sleep 5
echo "#######################"
echo "visit the servers IP in your browser to checkout liferay"
echo "try somehting like this:"
XIP=$(ifconfig | grep -A1 eth | grep inet | cut -d ":" -f2 | cut -d " " -f1)
echo "http://$XIP"
echo "#######################"
echo "To access awstats-site, use user awstats and your password - and find it on following site"
echo "http://$XIP/awstats/awstats.pl?config=$xdomain"
echo "#######################"
sleep 3
echo "DONE"
echo "HAVE FUN"