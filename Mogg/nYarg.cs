using System;
using System.IO;

namespace NautilusFREE
{
    public class YargMoggReadStream
    {
        public FileStream _fileStream;
        private readonly byte[] _baseEncryptionMatrix;
        private readonly byte[] _encryptionMatrix;
        private int _currentRow;

        public YargMoggReadStream(string path)
        {
            _fileStream = new FileStream(path, FileMode.Open, FileAccess.Read);

            // Get the encryption matrix
            var bytes = new byte[16];
            for (var i = 0; i < 16; i++)
            {
                bytes[i] = Convert.ToByte(_fileStream.ReadByte());
            }
            _baseEncryptionMatrix = bytes;
            //_baseEncryptionMatrix = _fileStream.ReadBytes(16);
            for (int i = 0; i < 16; i++)
            {
                _baseEncryptionMatrix[i] = (byte)Mod(_baseEncryptionMatrix[i] - i * 12, 255);
            }

            _encryptionMatrix = new byte[16];
            ResetEncryptionMatrix();
        }

        private void ResetEncryptionMatrix()
        {
            _currentRow = 0;
            for (int i = 0; i < 16; i++)
            {
                _encryptionMatrix[i] = _baseEncryptionMatrix[i];
            }
        }

        private void RollEncryptionMatrix()
        {
            int i = _currentRow;
            _currentRow = Mod(_currentRow + 1, 4);

            // Get the current and next matrix index
            int currentIndex = GetIndexInMatrix(i, i * 4);
            int nextIndex = GetIndexInMatrix(_currentRow, (i + 1) * 4);

            // Roll the previous row
            _encryptionMatrix[currentIndex] = (byte)Mod(
                _encryptionMatrix[currentIndex] +
                _encryptionMatrix[nextIndex],
                255);
        }

        public int Read(byte[] buffer, int offset, int count)
        {
            byte[] b = new byte[count];
            int read = _fileStream.Read(b, 0, count);

            // Decrypt
            for (int i = 0; i < read; i++)
            {
                // Parker-brown encryption window matrix
                int w = GetIndexInMatrix(_currentRow, i);

                // POWER!
                buffer[i] = (byte)(b[i] ^ _encryptionMatrix[w]);
                RollEncryptionMatrix();
            }

            return read;
        }        

        private static int Mod(int x, int m)
        {
            // C#'s % is rem not mod
            int r = x % m;
            return r < 0 ? r + m : r;
        }

        private static int GetIndexInMatrix(int x, int phi)
        {
            // Parker-brown encryption window matrix
            int y = x * x + 1 + phi;
            int z = x * 3 - phi;
            int w = y + z - x;
            if (w >= 16)
            {
                w = 15;
            }

            return w;
        }
    }
}
