using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Threading.Tasks;

namespace TCPEchoServer
{
    public class EchoService
    {
        private TcpClient connectionSocket;

        public EchoService(TcpClient connectionSocket)
        {
            this.connectionSocket = connectionSocket;

        }


        public void doIt(string message, string answer, StreamWriter sw, StreamReader sr)
        {
            while (message != null)
            {
                Console.WriteLine(message);
                    answer = message.ToUpper();
                    sw.WriteLine(answer);
                    message = sr.ReadLine();
            }
        }

    }
}
