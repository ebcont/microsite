#install microsite

apt-get install git
#git-core on ubuntu 10.04

mkdir -p /root/bin/git/microsite && cd /root/bin/git/microsite && git init
git --work-tree=/root/bin/git/microsite/ --git-dir=/root/bin/git/microsite/.git/ pull https://github.com/ebcont/microsite.git

cp /root/bin/git/microsite/microsite_credentials /root/bin/ && chmod 700 /root/bin/microsite_credentials


echo "10 0 * * *     root     ( cd /root/bin/git/microsite/ && git --work-tree=/root/bin/git/microsite/ --git-dir=/root/bin/git/microsite/.git/ pull https://github.com/ebcont/microsite.git )" >> /etc/crontab

