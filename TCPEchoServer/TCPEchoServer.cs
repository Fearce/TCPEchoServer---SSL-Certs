/*
 * TCPEchoServer
 *
 * Author Michael Claudius, ZIBAT Computer Science
 * Version 1.0. 2014.02.10
 * Copyright 2014 by Michael Claudius
 * Revised 2014.09.01
 * All rights reserved
 */


using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace TCPEchoServer
{
    class TCPEchoServer
    {

        public static void Main(string[] args)
        {

            //// IPAddress ip = new IPAddress("127.0.0.1");

            //IPAddress ip = IPAddress.Parse("127.0.0.1");


            // TcpListener serverSocket = new TcpListener(ip, 6789); //Only opens for 1 port (can only listen to one at a time?)
            // //Alternatively but deprecated
            // //TcpListener serverSocket = new TcpListener(6789);


            // serverSocket.Start();

            // Console.WriteLine("Server started");

            // TcpClient connectionSocket = serverSocket.AcceptTcpClient();
            //Socket connectionSocket = serverSocket.AcceptSocket();
            // Console.WriteLine("Server activated");

            // Stream ns = connectionSocket.GetStream();
            //// Stream ns = new NetworkStream(connectionSocket);

            // StreamReader sr = new StreamReader(ns);
            // StreamWriter sw = new StreamWriter(ns);
            // sw.AutoFlush = true; // enable automatic flushing

            //string message = sr.ReadLine();
            //string answer = "";
            //while (true)
            //{

            //    Console.WriteLine("Client: " + message);
            //    answer = message.ToUpper();
            //    sw.WriteLine(answer);
            //    message = sr.ReadLine();

            //}

            //ns.Close();
            //connectionSocket.Close();
            //serverSocket.Stop();

            TCPEchoServer1 server = new TCPEchoServer1();
            server.Main();


        }
    }
    
}


