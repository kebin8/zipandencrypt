using System.IO;
using System.IO.Compression;

namespace ZipandEncrpty
{
    public static class ZipUtil
    {
        /// <summary>
        /// Decompress a zip file to directory
        /// </summary>
        /// <param name="sourceFile"></param>
        /// <param name="destinationDirectory"></param>
        public static void DecompressToDirectory(string sourceFile, string destinationDirectory)
        {
            if (!File.Exists(sourceFile)) throw new FileNotFoundException();
            ZipFile.ExtractToDirectory(sourceFile, destinationDirectory);
        }
        
        /// <summary>
        /// Compress a directory to a zip file
        /// </summary>    
        /// <param name="sourceDirectory"></param>
        /// <param name="destinationFile"></param>
        public static void CompressFromDirectory(string sourceDirectory, string destinationFile)
        {
            if (!Directory.Exists(sourceDirectory)) throw new DirectoryNotFoundException();
            ZipFile.CreateFromDirectory(sourceDirectory, destinationFile);
        }        
    }
}
