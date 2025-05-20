using System;
using System.Net.Sockets;
using System.Net;

namespace LiteModbus;

struct NetworkConnectionParameter {
    public NetworkStream stream;        //For TCP-Connection only
    public Byte[] bytes;
    public int portIn;                  //For UDP-Connection only
    public IPAddress ipAddressIn;       //For UDP-Connection only
}
