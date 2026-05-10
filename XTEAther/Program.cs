using System.Collections;
using System.Globalization;
using System.Resources;
using System.Runtime.InteropServices;
using System.Text;
using XTEAther.Properties;

namespace XTEAther
{
    public static class Program
    {
        const uint ExpectedFileSize = 0x2E33400;

        const uint OepRva = 0x01031D5E;
        const uint ImportDirectoryRva = 0x01D58000;
        const uint ImportDirectorySize = 0x00000154;
        const uint RelocationDirectoryRva = 0x01D62000;
        const uint RelocationDirectorySize = 0x002248DC;

        const uint XteaDelta = 0x9E3779B9;
        const int XteaRounds = 32;

        private static readonly uint[] XteaKey = [0x0F53BE57, 0x6EF735DE, 0xBFFB1EFA, 0xD1D18AC1];

        private static readonly string[] EncryptedSections = [".text", ".idata", ".reloc"];
        private static readonly string[] AllowedSections = [".text", ".rdata", ".data", ".idata", ".tls", ".rsrc", ".reloc"];

        public static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: XTEAther <input-file>");
                return;
            }

            string input = args[0];
            string backup = input + ".bak";
            string output = input;

            if (!File.Exists(input))
            {
                Console.WriteLine($"Not found: {input}");
                return;
            }

            if (File.Exists(backup))
            {
                Console.WriteLine($"Backup already exists: {backup}");
                Console.ReadLine();
                return;
            }

            byte[] raw = File.ReadAllBytes(input);

            if (!IsValidPE(raw))
            {
                Console.WriteLine($"{input} doesn't look like a valid PE file.");
                Console.ReadLine();
                return;
            }

            if (raw.Length != ExpectedFileSize)
            {
                Console.WriteLine($"Unsupported file size 0x{raw.Length:X}, nothing to do.");
                Console.ReadLine();
                return;
            }

            File.Move(input, backup);

            Console.WriteLine("Decrypting sections...");
            DecryptSections(raw);

            Console.WriteLine("Applying devirtualized blobs...");
            ApplyDevirtualizedBlobs(raw);

            Console.WriteLine("Stripping DRM sections...");
            StripDrmSections(ref raw);

            Console.WriteLine("Restoring PE header...");
            RestoreHeader(raw);

            File.WriteAllBytes(output, raw);
            Console.WriteLine();
            Console.WriteLine($"Wrote output to {output}");
            Console.WriteLine($"Original file backed up as {backup}");
            Console.ReadLine();
        }

        #region Phase 1 – XTEA decrypt

        private static void DecryptSections(byte[] raw)
        {
            int ntHeadersOffset = ToInt32(raw, 0x3C);
            int sectionCount = ToInt16(raw, ntHeadersOffset + 4 + 2);
            int optionalHeaderSize = ToInt16(raw, ntHeadersOffset + 4 + 16);
            int sectionTableOffset = ntHeadersOffset + 4 + 20 + optionalHeaderSize;

            for (int i = 0; i < sectionCount; i++)
            {
                int sectionHeaderOffset = sectionTableOffset + i * 40;
                string name = Encoding.UTF8.GetString(raw, sectionHeaderOffset, 8).TrimEnd('\0');
                if (!EncryptedSections.Contains(name)) continue;

                int sectionSize = ToInt32(raw, sectionHeaderOffset + 16);
                int pointerToRawData = ToInt32(raw, sectionHeaderOffset + 20);

                int length = (sectionSize / 8) * 8;
                if (length <= 0) continue;

                XteaDecrypt(raw.AsSpan(pointerToRawData, length), XteaKey);

                Console.WriteLine($"    {name}: decrypted 0x{length:X} bytes at 0x{pointerToRawData:X}");
            }
        }

        public static void XteaDecrypt(Span<byte> data, ReadOnlySpan<uint> key)
        {
            if (data.Length % 8 != 0)
                throw new ArgumentException("Data length must be a multiple of 8 bytes");

            Span<uint> blocks = MemoryMarshal.Cast<byte, uint>(data);

            uint v0 = 0;
            uint v1 = 0;
            uint sum = 0;

            for (int i = 0; i < blocks.Length; i += 2)
            {
                for (int round = 0; round < XteaRounds; round++)
                {
                    v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[(int)(sum & 3)]);
                    sum += XteaDelta;
                    v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(int)((sum >> 11) & 3)]);
                }

                blocks[i] ^= v0;
                blocks[i + 1] ^= v1;
            }
        }

        #endregion

        #region Phase 2 – Apply devirtualized blobs to .text

        private static void ApplyDevirtualizedBlobs(byte[] raw)
        {
            int sectionHeaderOffset = SectionOffset(raw, ".text");
            if (sectionHeaderOffset < 0)
            {
                Console.WriteLine("    No .text section found.");
                return;
            }

            int sectionSize = ToInt32(raw, sectionHeaderOffset + 16);
            int pointerToRawData = ToInt32(raw, sectionHeaderOffset + 20);

            ResourceSet? set = Resources.ResourceManager.GetResourceSet(CultureInfo.InvariantCulture, true, true);
            if (set == null)
            {
                Console.WriteLine("    No devirtualized resources found.");
                return;
            }

            int applied = 0;
            foreach (DictionaryEntry entry in set)
            {
                string name = (string)entry.Key;
                if (entry.Value is not byte[] blob) continue;

                if (!uint.TryParse(name, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint offsetIntoText)) continue;
                if (offsetIntoText + blob.Length > (uint)sectionSize) continue;

                Buffer.BlockCopy(blob, 0, raw, pointerToRawData + (int)offsetIntoText, blob.Length);
                applied++;
            }

            Console.WriteLine($"    Applied {applied} blobs.");
        }

        #endregion

        #region Phase 3 – Strip DRM sections

        private static void StripDrmSections(ref byte[] raw)
        {
            int ntHeadersOffset = ToInt32(raw, 0x3C);
            int sectionCount = ToInt16(raw, ntHeadersOffset + 4 + 2);
            int optionalHeaderSize = ToInt16(raw, ntHeadersOffset + 4 + 16);
            int sectionTableOffset = ntHeadersOffset + 4 + 20 + optionalHeaderSize;

            List<(string name, uint prd)> targets = [];
            for (int i = 0; i < sectionCount; i++)
            {
                int sectionHeaderOffset = sectionTableOffset + i * 40;
                string name = Encoding.UTF8.GetString(raw, sectionHeaderOffset, 8).TrimEnd('\0');
                if (Array.IndexOf(AllowedSections, name) < 0)
                {
                    uint pointerToRawData = (uint)ToInt32(raw, sectionHeaderOffset + 20);
                    targets.Add((name, pointerToRawData));
                }
            }

            targets.Sort((a, b) => b.prd.CompareTo(a.prd));

            foreach ((string name, _) in targets)
            {
                if (StripSection(ref raw, name))
                {
                    Console.WriteLine($"    Stripped section: {(name.Length == 0 ? "(unnamed)" : name)}");
                }
            }

            UpdateSizeOfImage(raw);
        }

        #endregion

        #region Phase 4 – Restore PE header fields

        private static void RestoreHeader(byte[] raw)
        {
            int ntHeadersOffset = ToInt32(raw, 0x3C);
            int optionalHeaderOffset = ntHeadersOffset + 4 + 20;

            Write32(raw, optionalHeaderOffset + 16, (int)OepRva);                             // AddressOfEntryPoint
            Write32(raw, optionalHeaderOffset + 64, 0);                                       // CheckSum

            int dataDirectoryOffset = optionalHeaderOffset + 96;
            Write32(raw, dataDirectoryOffset + 1 * 8 + 0, (int)ImportDirectoryRva);           // Import RVA
            Write32(raw, dataDirectoryOffset + 1 * 8 + 4, (int)ImportDirectorySize);          // Import size
            Write32(raw, dataDirectoryOffset + 5 * 8 + 0, (int)RelocationDirectoryRva);       // Base relocation RVA
            Write32(raw, dataDirectoryOffset + 5 * 8 + 4, (int)RelocationDirectorySize);      // Base relocation size
        }

        #endregion

        #region Section table helpers

        private static bool StripSection(ref byte[] raw, string name)
        {
            int sectionHeaderOffset = SectionOffset(raw, name);
            if (sectionHeaderOffset < 0) return false;

            int ntHeadersOffset = ToInt32(raw, 0x3C);
            int sectionCount = ToInt16(raw, ntHeadersOffset + 4 + 2);
            int optionalHeaderSize = ToInt16(raw, ntHeadersOffset + 4 + 16);
            int sectionTableOffset = ntHeadersOffset + 4 + 20 + optionalHeaderSize;
            int sectionIndex = (sectionHeaderOffset - sectionTableOffset) / 40;

            uint pointerToRawData = (uint)ToInt32(raw, sectionHeaderOffset + 20);

            bool isLastInFile = true;
            for (int i = 0; i < sectionCount; i++)
            {
                if (i == sectionIndex) continue;

                uint otherPointerToRawData = (uint)ToInt32(raw, sectionTableOffset + i * 40 + 20);
                if (otherPointerToRawData > pointerToRawData)
                {
                    isLastInFile = false;
                    break;
                }
            }

            if (sectionIndex < sectionCount - 1)
            {
                int length = (sectionCount - 1 - sectionIndex) * 40;
                Buffer.BlockCopy(raw, sectionHeaderOffset + 40, raw, sectionHeaderOffset, length);
            }

            Array.Clear(raw, sectionTableOffset + (sectionCount - 1) * 40, 40);

            int numberOfSectionsOffset = ntHeadersOffset + 4 + 2;
            short newSectionCount = (short)(ToInt16(raw, numberOfSectionsOffset) - 1);
            raw[numberOfSectionsOffset] = (byte)(newSectionCount & 0xFF);
            raw[numberOfSectionsOffset + 1] = (byte)(newSectionCount >> 8);

            if (isLastInFile && pointerToRawData < (uint)raw.Length)
            {
                Array.Resize(ref raw, (int)pointerToRawData);
            }

            return true;
        }

        private static void UpdateSizeOfImage(byte[] raw)
        {
            int ntHeadersOffset = ToInt32(raw, 0x3C);
            int optionalHeaderOffset = ntHeadersOffset + 4 + 20;
            uint sectionAlignment = (uint)ToInt32(raw, optionalHeaderOffset + 32);
            int sectionCount = ToInt16(raw, ntHeadersOffset + 4 + 2);
            int optionalHeaderSize = ToInt16(raw, ntHeadersOffset + 4 + 16);
            int sectionTableOffset = ntHeadersOffset + 4 + 20 + optionalHeaderSize;

            uint maxEnd = 0;
            for (int i = 0; i < sectionCount; i++)
            {
                int sectionHeaderOffset = sectionTableOffset + i * 40;
                uint virtualAddress = (uint)ToInt32(raw, sectionHeaderOffset + 12);
                uint virtualSize = (uint)ToInt32(raw, sectionHeaderOffset + 8);
                uint end = (virtualAddress + virtualSize + sectionAlignment - 1) & ~(sectionAlignment - 1);
                if (end > maxEnd) maxEnd = end;
            }

            Write32(raw, optionalHeaderOffset + 56, (int)maxEnd);
        }

        #endregion

        #region PE / byte helpers

        public static bool IsValidPE(byte[] raw)
        {
            if (raw[0] != 'M' || raw[1] != 'Z') return false;

            int ntHeadersOffset = ToInt32(raw, 0x3C);
            if (ntHeadersOffset < 0 || ntHeadersOffset + 4 + 20 + 2 > raw.Length) return false;
            if (raw[ntHeadersOffset] != 'P' || raw[ntHeadersOffset + 1] != 'E') return false;
            if (raw[ntHeadersOffset + 2] != 0 || raw[ntHeadersOffset + 3] != 0) return false;

            // 32-bit check
            int optionalHeaderOffset = ntHeadersOffset + 4 + 20;
            if (ToInt16(raw, optionalHeaderOffset) != 0x10B) return false;

            return true;
        }

        public static int SectionOffset(byte[] raw, string name)
        {
            int ntHeadersOffset = ToInt32(raw, 0x3C);
            int sectionCount = ToInt16(raw, ntHeadersOffset + 4 + 2);
            int optionalHeaderSize = ToInt16(raw, ntHeadersOffset + 4 + 16);
            int sectionTableOffset = ntHeadersOffset + 4 + 20 + optionalHeaderSize;

            for (int i = 0; i < sectionCount; i++)
            {
                int sectionHeaderOffset = sectionTableOffset + i * 40;
                if (Encoding.UTF8.GetString(raw, sectionHeaderOffset, 8).TrimEnd('\0') == name) return sectionHeaderOffset;
            }

            return -1;
        }

        public static int SectionRva(byte[] raw, string name)
        {
            int sectionHeaderOffset = SectionOffset(raw, name);
            return sectionHeaderOffset < 0 ? -1 : ToInt32(raw, sectionHeaderOffset + 12);
        }

        public static void Write32(byte[] buf, int i, int val)
        {
            buf[i] = (byte)val;
            buf[i + 1] = (byte)(val >> 0x08);
            buf[i + 2] = (byte)(val >> 0x10);
            buf[i + 3] = (byte)(val >> 0x18);
        }

        public static int ToInt32(byte[] buf, int i)
        {
            return buf[i] | (buf[i + 1] << 8) | (buf[i + 2] << 16) | (buf[i + 3] << 24);
        }

        public static short ToInt16(byte[] buf, int i)
        {
            return (short)(buf[i] | (buf[i + 1] << 8));
        }

        #endregion
    }
}