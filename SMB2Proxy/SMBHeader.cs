using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace SMB2Proxy
{
    //https://msdn.microsoft.com/en-us/library/cc246528.aspx
    class SMBHeader
    {
        public SMBHeader(Stream s)
        {
            using (var reader = new BinaryReader(s, Encoding.Unicode, leaveOpen:true))
            {
                ProtocolId = reader.ReadBytes(4);
                if (!ProtocolId.SequenceEqual(StandardProcolId))
                {
                    throw new ArgumentException("protocol started with " + BitConverter.ToString(ProtocolId));
                }

                StructureSize = reader.ReadUInt16();
                CreditCharge = reader.ReadUInt16();
                ChannelSequence = reader.ReadUInt16();

                reader.ReadUInt16(); //reserved
                Command = (SMB2Command)reader.ReadUInt16();
                CreditRequestResponse  = reader.ReadUInt16();
                Flags = (SMB2Flags)reader.ReadUInt32();
                NextCommand = reader.ReadUInt32();
                MessageId = reader.ReadUInt64();
                reader.ReadUInt32(); //reserved
                TreeId = reader.ReadUInt32();
                SessionId = reader.ReadUInt64();
                Signature = reader.ReadBytes(16);
            }
        }

        public SMBHeader(SMB2Command cmd, ulong msgId)
        {
            Command = cmd;
            MessageId = msgId;
            Flags = SMB2Flags.SERVER_TO_REDIR; //this is a response
            CreditRequestResponse = 1;
        }

        public void Write(Stream s)
        {
            using (var writer = new BinaryWriter(s, Encoding.Unicode, leaveOpen: true))
            {

                writer.Write(StandardProcolId);
                
                writer.Write(StructureSize);
                writer.Write(CreditCharge);
                writer.Write(ChannelSequence);

                writer.Write((ushort)0);// reserved
                writer.Write((ushort)Command);
                writer.Write(CreditRequestResponse);
                writer.Write((uint)Flags);
                writer.Write(NextCommand);
                writer.Write(MessageId);
                writer.Write((uint)0); //reserveed
                writer.Write(TreeId);
                writer.Write(SessionId);
                writer.Write(Signature);
            }
        }

        readonly byte[] StandardProcolId = new byte[] { 0xFE, 0x53, 0x4D, 0x42 };

        byte[] ProtocolId = new byte[4];
        public ushort StructureSize = 64;
        ushort CreditCharge = 0;
        ushort ChannelSequence ;
        public SMB2Command Command;
        ushort CreditRequestResponse;
        SMB2Flags Flags;
        uint NextCommand;
        public ulong MessageId;
        uint TreeId; //or async id?
        ulong SessionId;
        byte[] Signature = new byte[16];

        public override string ToString()
        {
            return String.Format("Command {0}, Flags {1}, Message {2}", Command, Flags, MessageId);
        }

    }

    enum SMB2Command : ushort
    {
        NEGOTIATE = 0x00, 
        SESSION_SETUP = 0x01,
        LOGOFF = 0x02,
        TREE_CONNECT = 0x03,
        TREE_DISCONNECT =  0x04,
        CREATE = 0x05,
        CLOSE = 0x06,
        FLUSH = 0x07,
        READ = 0x08,
        WRITE = 0x09,
        LOCK = 0x0A,
        IOCTL = 0x0B,
        CANCEL = 0x0C,
        ECHO = 0x0D,
        QUERY_DIRECTORY = 0x0E,
        CHANGE_NOTIFY = 0x0F,
        QUERY_INFO = 0x10,
        SET_INFO = 0x11,
        OPLOCK_BREAK = 0x12,
    }

    [FlagsAttribute] 
    enum SMB2Flags : uint
    {
        None = 0,
        SERVER_TO_REDIR = 1,
        ASYNC_COMMAND = 2,
        RELATED_OPERATIONS = 4,
        SIGNED = 8,
        DFS_OPERATIONS = 0x10000000,
        REPLAY_OPERATION = 0x20000000 
    }
}
