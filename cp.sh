#! /usr/bin/expect

# 设置超时时间
set timeout 3
# fork一个子进程执行ssh
spawn scp server root@10.9.104.111:/code/gnutls-demo
expect "*password*"
send "nucleus\r"
expect eof

spawn scp client root@10.9.104.101:/code/gnutls-demo
expect "*password*"
send "nucleus\r"
expect eof