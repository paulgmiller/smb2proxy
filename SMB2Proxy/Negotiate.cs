using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace SMB2Proxy
{
    //https://msdn.microsoft.com/en-us/library/cc246528.aspx
    class NegotiateRequest
    {
        public NegotiateRequest(Stream s)
        {
            using (var reader = new BinaryReader(s, Encoding.Unicode, leaveOpen:true))
            {
                StructureSize = reader.ReadUInt16();
                DialectCount = reader.ReadUInt16();
                SecurityMode = reader.ReadUInt16();
                Reserved = reader.ReadUInt16();
                Capabilities = reader.ReadUInt32();
                ClientGuid = reader.ReadBytes(16);
                ClientStartTime = reader.ReadUInt64();
                for (int d=0; d <  DialectCount; ++d)
                {
                    dialects.Add(reader.ReadUInt16());
                }
            }
        }
    
        ushort StructureSize ;
        ushort DialectCount ;
        ushort SecurityMode ;
        ushort Reserved;
        uint Capabilities;
        byte[] ClientGuid = new byte[16];
        ulong ClientStartTime;
        List<ushort> dialects = new List<ushort>();
        byte[] Signature = new byte[16];

        public override string ToString()
        {
            return string.Format("{0} dialects: {1} and size {2}", DialectCount, string.Join(",", dialects), StructureSize);
        }

        
    }

    class NegotiateResponse
    {
        public NegotiateResponse()
        {   
        }

        public void Write(Stream s)
        {
            using (var writer = new BinaryWriter(s, Encoding.Unicode, leaveOpen: true))
            {
                writer.Write(StructureSize);
                writer.Write(SecurityMode);
                writer.Write(DialectRevision);
                writer.Write((ushort)0);
                writer.Write(ServerGuid.ToByteArray());
                writer.Write(Capabilites);
                writer.Write(MaxTransactSize);
                writer.Write(MaxReadSize);
                writer.Write(MaxWriteSize);
                writer.Write(SystemTime);
                writer.Write(ServerStartTime);
                writer.Write(SecurityBufferOffset);
                writer.Write(SecurityBufferLength);
                writer.Write((uint)0);
            }
        }

        public ushort StructureSize = 65;
        ushort SecurityMode = 0;
        ushort DialectRevision = 0x0210;
        //ushort Reserved;
        Guid ServerGuid = Program.ServerGuid;
        uint Capabilites = 0;
        uint MaxTransactSize = 0x8000;
        uint MaxReadSize = 0x8000;
        uint MaxWriteSize = 0x8000;
        long SystemTime = DateTime.Now.ToFileTime();
        long ServerStartTime  = Program.StartTime;
        ushort SecurityBufferOffset = 17*4;
        ushort SecurityBufferLength = 0;
        //unint reserved
        //security buffer

        /*public override string ToString()
        {
            new MemoryStream(); 
            return string.Format("{0} dialects: {1} and size {2}", DialectCount, string.Join(",", dialects), StructureSize);
        }*/


    }

}
