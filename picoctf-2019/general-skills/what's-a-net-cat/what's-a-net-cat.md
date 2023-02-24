# what's a net cat?

## Problem Description
Using netcat (nc) is going to be pretty important. Can you connect to `jupiter.challenges.picoctf.org` at port `41120` to get the flag?

| Points  | Category| Author |
| ------------- | ------------- | ------------- |
| 100  | General Skills  | Kaden Wu |

### Writeup 
PicoCTF often uses a tool called netcat. It’s a tool that uses [TCP/UDP](https://www.digitalocean.com/community/tutorials/how-to-use-netcat-to-establish-and-test-tcp-and-udp-connections) connections to read and write on a server. To function, netcat needs a server and a port. The format for using netcat ([link to man page](https://linux.die.net/man/1/nc)) is:

`nc <hostname> <port>` where hostname denotes the name of the server and port denotes the port number

In this case, the hostname is `jupiter.challenges.picoctf.org` and the port is `41120`, so to type the command, you would type this into the webshell:

`nc jupiter.challenges.picoctf.org 44120`

After typing this, you are left with this message:

```
You're on your way to becoming the net cat master

picoCTF{nEtCat_Mast3ry_3214be47}
```

As such, we have our flag, which is wrapped in `picoCTF{...}`.

```
picoCTF{nEtCat_Mast3ry_3214be47}
```
