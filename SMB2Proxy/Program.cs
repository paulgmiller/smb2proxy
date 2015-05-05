using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace SMB2Proxy
{
    class Program
    {
        static void Main(string[] args)
        {
    
          // TcpListener server = new TcpListener(port);
          var server = new TcpListener(IPAddress.Any, 445);

          // Start listening for client requests.
          server.Start();

          // Enter the listening loop. 
          while(true) 
          {
            Console.Write("Waiting for a connection... ");

            // Perform a blocking call to accept requests. 
            // You could also user server.AcceptSocket() here.
            TcpClient client = server.AcceptTcpClient();            
            Console.WriteLine("Connected!");

            
            // Get a stream object for reading and writing
            NetworkStream stream = client.GetStream();
            //https://msdn.microsoft.com/en-us/library/cc246249.aspx 
            var junk  = new Byte[4];
            stream.Read(junk, 0, 4);

            var header = new SMBHeader(stream);
            Console.WriteLine("Received: {0}", header.ToString());
            if (header.Command == SMB2Command.NEGOTIATE)
            {
                var neg = new NegotiateRequest(stream);
                Console.WriteLine("Negotiate: {0}", neg.ToString());
                var respHeader = new SMBHeader(SMB2Command.NEGOTIATE, header.MessageId);
                var resp = new NegotiateResponse();
                
 
                uint packetlength = (uint)respHeader.StructureSize + resp.StructureSize;
                byte[] bytes = new byte[3];

                bytes[0] = (byte)(packetlength >> 16);
                bytes[1] = (byte)(packetlength >> 8);
                bytes[2] = (byte)(packetlength);

                
                stream.WriteByte(0);
                stream.Write(bytes, 0, 3);
                respHeader.Write(stream);
                resp.Write(stream);
                

                /*{
                    var memstream = new MemoryStream();
                    memstream.WriteByte(0);
                    memstream.Write(bytes, 0, 3);
                    respHeader.Write(memstream);
                    resp.Write(memstream);

                    memstream.Close();
                    Console.WriteLine(BitConverter.ToString(memstream.ToArray()));
                }*/

            }
            else 
            {
                Console.WriteLine("Can't handle " + header.Command);
            }

            Console.WriteLine("keep reading");
            byte[] funk = new byte[1];
            while(stream.Read(funk, 0, funk.Length)!=0) 
            {
                Console.WriteLine(BitConverter.ToString(funk));
            }

            
            // Shutdown and end connection
            client.Close();
          }

        }

        public static Guid ServerGuid = Guid.NewGuid();
        public static long StartTime = DateTime.Now.ToFileTime();
    }
}
