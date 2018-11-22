using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace TCPEchoServer
{
    class TCPEchoServer1
    {
        public TcpClient connectionSocket;

        public void Main()
        {
            // IPAddress ip = new IPAddress("127.0.0.1");

            IPAddress ip = IPAddress.Parse("127.0.0.1");


            TcpListener serverSocket = new TcpListener(ip, 6789); //Only opens for 1 port (can only listen to one at a time?)
            //Alternatively but deprecated
            //TcpListener serverSocket = new TcpListener(6789);


            serverSocket.Start();
           

            while (true)
            {
                try
                {   
                    //Alternatively just
                    //sslStream.AuthenticateAsServer(serverCertificate)

                    Console.WriteLine("Server started");

                    TcpClient connectionSocket = serverSocket.AcceptTcpClient();


                    Task.Run(() =>
                    {
                        //Socket connectionSocket = serverSocket.AcceptSocket();
                        Console.WriteLine("Server activated");

                        #region ssl stuff
                        string serverCertificateFile = "c:/certificates/ServerSSL.cer";
                        if (!File.Exists(serverCertificateFile))
                        {
                            throw new FileNotFoundException("bad file");
                        }
                        bool clientCertificateRequired = true;
                        bool checkCertificateRevocation = false;
                        SslProtocols enabledSSLProtocols = SslProtocols.Tls;
                        X509Certificate serverCertificate = new X509Certificate(serverCertificateFile, "secret");

                        bool CertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
                        {
                            if (sslPolicyErrors != SslPolicyErrors.None)
                            {
                                Console.WriteLine("SSL Certificate Validation Error!");
                                Console.WriteLine(sslPolicyErrors.ToString());
                                Debug.WriteLine(sslPolicyErrors.ToString());
                                return false;
                            }
                            else
                                return true;
                        }
                            
                        Stream unsecureStream = connectionSocket.GetStream();

                        X509Certificate CertificateSelectionCallback(object sender,
                            string targetHost,
                            X509CertificateCollection localCertificates,
                            X509Certificate remote,
                            string[] acceptableIssuers)
                        {
                            return serverCertificate;
                        }

                        bool CertificateValidationCallBack(
               object sender,
               System.Security.Cryptography.X509Certificates.X509Certificate certificate,
               System.Security.Cryptography.X509Certificates.X509Chain chain,
               System.Net.Security.SslPolicyErrors sslPolicyErrors)
                        {
                            // If the certificate is a valid, signed certificate, return true.
                            if (sslPolicyErrors == System.Net.Security.SslPolicyErrors.None)
                            {
                                return true;
                            }

                            // If there are errors in the certificate chain, look at each error to determine the cause.
                            if ((sslPolicyErrors & System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors) != 0)
                            {
                                if (chain != null && chain.ChainStatus != null)
                                {
                                    foreach (System.Security.Cryptography.X509Certificates.X509ChainStatus status in chain.ChainStatus)
                                    {
                                        if ((certificate.Subject == certificate.Issuer) &&
                                            (status.Status == System.Security.Cryptography.X509Certificates.X509ChainStatusFlags.UntrustedRoot))
                                        {
                                            // Self-signed certificates with an untrusted root are valid. 
                                            continue;
                                        }
                                        else
                                        {
                                            if (status.Status != System.Security.Cryptography.X509Certificates.X509ChainStatusFlags.NoError)
                                            {
                                                // If there are any other errors in the certificate chain, the certificate is invalid,
                                                // so the method returns false.
                                                return false;
                                            }
                                        }
                                    }
                                }

                                // When processing reaches this line, the only errors in the certificate chain are 
                                // untrusted root errors for self-signed certificates. These certificates are valid
                                // for default Exchange server installations, so return true.
                                return true;
                            }
                            else
                            {
                                // In all other cases, return false.
                                return false;
                            }
                        }



                        bool leaveInnerStreamOpen = false;
                        SslStream sslStream = new SslStream(unsecureStream, leaveInnerStreamOpen, CertificateValidationCallBack, CertificateSelectionCallback);
                        sslStream.AuthenticateAsServer(serverCertificate, clientCertificateRequired, enabledSSLProtocols, checkCertificateRevocation);
                        //sslStream.AuthenticateAsServer(serverCertificate); //PLS HELP The server mode SSL must use a certificate with the associated private key.

                        #endregion


                        Stream ns = connectionSocket.GetStream();
                        // Stream ns = new NetworkStream(connectionSocket);

                        //StreamReader sr = new StreamReader(ns); //old without ssl
                        StreamReader sr = new StreamReader(sslStream); //new with ssl
                        StreamWriter sw = new StreamWriter(sslStream);
                        sw.AutoFlush = true; // enable automatic flushing
                        string message = sr.ReadLine();
                        string answer = "";
                        EchoService echoSvc = new EchoService(connectionSocket);
                        echoSvc.doIt(message, answer, sw, sr);
                    });
                    
                }
                catch (Exception IOException)
                {
                    Console.WriteLine("Client shut down, restarting");
                    serverSocket.Stop();
                    Main();
                }

                
            }

        }
    }
}
