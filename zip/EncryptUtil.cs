using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;

namespace ZipandEncrpty
{
    public static class EncryptUtil
    {
        ///<summary>
        /// Streaming encrypts a file using pgp public key file.
        ///</summary>
        ///<param name="inputFile"></param>
        ///<param name="outputFile"></param>
        ///<param name="publicKeyFile"></param>
        ///<param name="armor"></param>
        ///<param name="withIntegrityCheck"></param>
        public static void EncryptFile(string inputFile, string outputFile, string publicKeyFile, bool armor, bool withIntegrityCheck)
        {
            Stream fileStream = new FileStream(outputFile, FileMode.Create);
            Stream outputStream = fileStream;

            if (armor)
            {
                outputStream = new ArmoredOutputStream(fileStream);
            }

            try
            {
                PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());
                PgpPublicKey encKey = ReadPublicKey(File.OpenRead(publicKeyFile));
                cPk.AddMethod(encKey);

                Stream cOut = cPk.Open(outputStream, new byte[1 << 16]);

                PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(
                    CompressionAlgorithmTag.Zip);

                PgpUtilities.WriteFileToLiteralData(
                    comData.Open(cOut),
                    PgpLiteralData.Binary,
                    new FileInfo(inputFile),
                    new byte[1 << 16]);

                comData.Close();

                cOut.Close();
            }
            catch (PgpException e)
            {
                throw;
            }
            finally
            {
                if (outputStream != null)
                {
                    outputStream.Close();
                }
                if (fileStream != null)
                {
                    fileStream.Close();
                }
            }
        }

        /*
        ///<summary>
        /// Encrypts a file using pgp public key file. if the file is large, it will thorw out of memory error
        ///</summary>
        ///<param name="inputFile"></param>
        ///<param name="outputFile"></param>
        ///<param name="publicKeyFile"></param>
        ///<param name="armor"></param>
        ///<param name="withIntegrityCheck"></param>
        public static void EncryptFile(string inputFile, string outputFile, string publicKeyFile, bool armor, bool withIntegrityCheck)
        {
            try
            {
                using (Stream publicKeyStream = File.OpenRead(publicKeyFile))
                {
                    PgpPublicKey encKey = ReadPublicKey(publicKeyStream);

                    using (MemoryStream bOut = new MemoryStream())
                    {
                        PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
                        PgpUtilities.WriteFileToLiteralData(comData.Open(bOut), PgpLiteralData.Binary, new FileInfo(inputFile));

                        comData.Close();
                        PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());

                        cPk.AddMethod(encKey);
                        byte[] bytes = bOut.ToArray();

                        using (Stream outputStream = File.Create(outputFile))
                        {
                            if (armor)
                            {
                                using (ArmoredOutputStream armoredStream = new ArmoredOutputStream(outputStream))
                                {
                                    using (Stream cOut = cPk.Open(armoredStream, bytes.Length))
                                    {
                                        cOut.Write(bytes, 0, bytes.Length);
                                    }
                                }
                            }
                            else
                            {
                                using (Stream cOut = cPk.Open(outputStream, bytes.Length))
                                {
                                    cOut.Write(bytes, 0, bytes.Length);
                                }
                            }
                        }
                    }
                }
            }
            catch (PgpException e)
            {
                throw;
            }
        }*/

        private static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            // iterate through the key rings.
            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey k in kRing.GetPublicKeys())
                {
                    if (k.IsEncryptionKey)
                        return k;
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        public static void Decrypt(string inputfile, string privateKeyFile, string passPhrase, string outputFile)
        {
            if (!File.Exists(inputfile))
                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputfile));

            if (!File.Exists(privateKeyFile))
                throw new FileNotFoundException(String.Format("Private Key File [{0}] not found.", privateKeyFile));

            if (String.IsNullOrEmpty(outputFile))
                throw new ArgumentNullException("Invalid Output file path.");

            using (Stream inputStream = File.OpenRead(inputfile))
            {
                using (Stream keyIn = File.OpenRead(privateKeyFile))
                {
                    Decrypt(inputStream, keyIn, passPhrase, outputFile);
                }
            }
        }

        public static void Decrypt(Stream inputStream, Stream privateKeyStream, string passPhrase, string outputFile)
        {
            try
            {
                PgpObjectFactory pgpF = null;
                PgpEncryptedDataList enc = null;
                PgpObject o = null;
                PgpPrivateKey sKey = null;
                PgpPublicKeyEncryptedData pbe = null;
                PgpSecretKeyRingBundle pgpSec = null;

                pgpF = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
                // find secret key
                pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

                if (pgpF != null)
                    o = pgpF.NextPgpObject();

                // the first object might be a PGP marker packet.
                if (o is PgpEncryptedDataList)
                    enc = (PgpEncryptedDataList)o;
                else
                    enc = (PgpEncryptedDataList)pgpF.NextPgpObject();

                // decrypt
                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {
                    sKey = FindSecretKey(pgpSec, pked.KeyId, passPhrase.ToCharArray());

                    if (sKey != null)
                    {
                        pbe = pked;
                        break;
                    }
                }

                if (sKey == null)
                    throw new ArgumentException("Secret key for message not found.");

                PgpObjectFactory plainFact = null;

                using (Stream clear = pbe.GetDataStream(sKey))
                {
                    plainFact = new PgpObjectFactory(clear);
                }

                PgpObject message = plainFact.NextPgpObject();

                if (message is PgpCompressedData)
                {
                    PgpCompressedData cData = (PgpCompressedData)message;
                    PgpObjectFactory of = null;

                    using (Stream compDataIn = cData.GetDataStream())
                    {
                        of = new PgpObjectFactory(compDataIn);
                    }

                    message = of.NextPgpObject();
                    if (message is PgpOnePassSignatureList)
                    {
                        message = of.NextPgpObject();
                        PgpLiteralData Ld = null;
                        Ld = (PgpLiteralData)message;
                        using (Stream output = File.Create(outputFile))
                        {
                            Stream unc = Ld.GetInputStream();
                            Streams.PipeAll(unc, output);
                        }
                    }
                    else
                    {
                        PgpLiteralData Ld = null;
                        Ld = (PgpLiteralData)message;
                        using (Stream output = File.Create(outputFile))
                        {
                            Stream unc = Ld.GetInputStream();
                            Streams.PipeAll(unc, output);
                        }
                    }
                }
                else if (message is PgpLiteralData)
                {
                    PgpLiteralData ld = (PgpLiteralData)message;
                    string outFileName = ld.FileName;

                    using (Stream fOut = File.Create(outputFile))
                    {
                        Stream unc = ld.GetInputStream();
                        Streams.PipeAll(unc, fOut);
                    }
                }
                else if (message is PgpOnePassSignatureList)
                    throw new PgpException("Encrypted message contains a signed message - not literal data.");
                else
                    throw new PgpException("Message is not a simple encrypted file - type unknown.");
            }
            catch (PgpException ex)
            {
                throw;
            }
        }

        private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);

            if (pgpSecKey == null)
                return null;

            return pgpSecKey.ExtractPrivateKey(pass);
        }
    }
}
