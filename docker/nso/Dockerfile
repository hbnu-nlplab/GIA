FROM cisco-nso-dev:6.6

# ssh-rsa 패치: ncs-setup 후 ncs.conf에 ssh-rsa 추가
COPY entrypoint-ssh-rsa.sh /root/entrypoint.sh
RUN chmod +x /root/entrypoint.sh

ENTRYPOINT ["/root/entrypoint.sh"]
