## SLC (Socket Lost Control)

### Basic Usage


### Funtion
The function of SLC is to make isolated space accessible via IP + public port (TCP only). Similar to socat, but more scalable, multithreaded and reusable. Use case not only SSH, all applications that use TCP can be integrated with SLC.

> What kind of isolated room, for example?

Any environment does not have access to login via public IP. For example isolated docker whose ports are not exposed to the public.
Even a personal laptop can.
The important thing is that there is an internet connection.

This is for conditions that can be accessed from the outside, but cannot be accessed from the outside.

> like wireguard/tailscale.com

Practically all VPNs should do that. Only the VPN needs to touch the network layer. In other words, it is necessary to create a virtual network interface. If SLC is only an application layer, it only requires TCP sockets.

The way it works is to connect data between socket descriptor files (+ logging to support multiple clients):
```
   fd1 -> fd2
   fd2 -> fd1
```
The event loop is polling for `POLLIN | POLLPRI` event of 2 file descriptors. If any data is entered in `fd1`, consume the data, write to `fd2`. And vice versa too.

> but what is the function of the server there for?

Here's how it works, use stories to make it fun:

1) The isolated client has an SSHD on port 22. Not accessible from outside.
2) Server in SLC, SLC need to listen 2 ports:
     - Port circuit (leave 8888).
     - Public port (leave 9999).
3) Isolated client turn on SLC, connect to server port 8888.
4) I SSH login via the server's public IP to port 9999.
5) Through the port circuit, the server says, "hey, open a connection again for SSH".
6) The isolated client creates a new TCP socket, connecting to port 8888 with a handshake containing a unique identifier for the hash table (this connection is specific to the handle number (4), all packets are forwarded to port 22).

> full P2P without server right?

Can not. You need Tor if that's the case (Tor actually has servers too)
