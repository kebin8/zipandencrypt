using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ZipandEncrpty
{
    class Program
    {
        static void Main(string[] args)
        {
            ZipUtil.CompressFromDirectory("E:\\a", "E:\\a.zip");
            EncryptUtil.EncryptFile("E:\\a.zip", "E:\\a.zip.pgp", "E:\\0x5EE39C0B-pub.asc", true, true);
            EncryptUtil.Decrypt("E:\\a.zip.pgp", "E:\\0x5EE39C0B-sec.asc", "123456", "E:\\aa.zip");
        }
    }
}