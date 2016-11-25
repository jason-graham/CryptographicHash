//---------------------------------------------------------------------------- 
//
//  Copyright (C) Jason Graham.  All rights reserved.
// 
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
// 
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
// 
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
// 
// History
//  05/20/13    Created 
//
//---------------------------------------------------------------------------

namespace System.Security.Cryptography
{
    using System.Diagnostics;
    using System.IO;
    using System.Runtime.Serialization;

    /// <summary>
    /// Hash base class used for initialization and hash code formatting.
    /// </summary>
    /// <typeparam name="T">The type of hash this represents.</typeparam>
    [DebuggerDisplay("Hash Code = {ToString(\"D\")}")]
    [Serializable]
    public abstract class CryptographicHash<T> : IComparable, IComparable<CryptographicHash<T>>, IEquatable<CryptographicHash<T>> where T : CryptographicHash<T>
    {
        #region Fields
        /// <summary>
        /// Defines the underlying hash code this instance represents.
        /// </summary>
        private string HashCode;
        #endregion

        #region Properties
        /// <summary>
        /// Gets or sets the hash value in bytes.
        /// </summary>
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private byte[] HashValue
        {
            get
            {
                //packs the hash code into a byte array
                byte[] result = new byte[HashCode.Length / 2];

                //bitwise OR two hex values into a byte
                for (int i = 0; i < result.Length; i++)
                    result[i] = (byte)(FromHex(HashCode[i * 2]) << 4 | FromHex(HashCode[i * 2 + 1]));

                return result;
            }
            set
            {
                //unpacks the byte array into a hash code
                char[] result = new char[value.Length * 2];

                for (int i = 0; i < result.Length; i += 2)
                {
                    result[i] = ToHex((byte)(value[i / 2] >> 4));
                    result[i + 1] = ToHex(value[i / 2]);
                }

                HashCode = new string(result);
            }
        }

        /// <summary>
        /// Gets the hash length in characters.
        /// </summary>
        public abstract int HashCodeSize
        {
            get;
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Initializes the hash using a hash code.
        /// </summary>
        /// <param name="hashCode">The hash code.</param>
        public CryptographicHash(string hashCode)
        {
            if (hashCode == null)
                throw new ArgumentNullException("hashValue");

            if (!IsHashCodeValid(hashCode, GetHashCodeSize(), out HashCode))
                throw new ArgumentException("The hash code is an invalid hash code for the hash implementation", "hashCode");
        }

        /// <summary>
        /// Initializes the hash using a hash value.
        /// </summary>
        /// <param name="hashValue">The hash value.</param>
        public CryptographicHash(byte[] hashValue)
        {
            if (hashValue == null)
                throw new ArgumentNullException("hashValue");

            if (!IsHashCodeValid(hashValue, GetHashCodeSize()))
                throw new ArgumentException("The hash value is an invalid hash code for the hash implementation", "hashValue");

            HashValue = hashValue;
        }
        #endregion

        #region Methods
        #region Hash Validation
        /// <summary>
        /// Determines if the hash code is valid and returns a hash by reference with any separators stripped.
        /// </summary>
        /// <param name="hashCode">The hash code to validate.</param>
        /// <param name="expectedHashSize">The expected hash code size without separators.</param>
        /// <param name="fixedHash">When this method returns, contains the hashCode without any separators.</param>
        /// <returns>true if the hash code is valid; otherwise, false.</returns>
        private static bool IsHashCodeValid(string hashCode, int expectedHashSize, out string fixedHash)
        {
            fixedHash = null;

            int length = hashCode.Length;
            if (length != expectedHashSize && length != expectedHashSize + expectedHashSize / 4 - 1)
                return false;

            bool flag = false;
            int separatorIndex = 4;
            int offset = 0;
            char[] hash = new char[expectedHashSize];

            for (int i = 0; i < length; i++)
            {
                if (i == separatorIndex)
                {
                    if (hashCode[i] == '-')
                    {
                        separatorIndex += 5;
                        offset++;
                        flag = true;
                        continue;
                    }
                    else if (flag)
                        return false;
                }

                if (!IsHexChar(hashCode[i]))
                    return false;

                hash[i - offset] = hashCode[i];
            }

            fixedHash = new string(hash);
            return true;
        }

        /// <summary>
        /// Determines if the hash value is valid.
        /// </summary>
        /// <param name="hashValue">The hash value to validate.</param>
        /// <param name="expectedHashSize">The expected hash code size without separators.</param>
        /// <returns>true if the hash value is valid; otherwise, false.</returns>
        private static bool IsHashCodeValid(byte[] hashValue, int expectedHashSize)
        {
            return hashValue.Length == expectedHashSize / 2;
        }

        /// <summary>
        /// Determines if the character is a valid hex character.
        /// </summary>
        /// <param name="c">The character to validate;</param>
        /// <returns>true if the character is a valid hex character; otherwise, false.</returns>
        private static bool IsHexChar(char c)
        {
            return (c >= 'a' && c <= 'f') || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F');
        }
        #endregion

        #region TryParse Methods
        /// <summary>
        /// Converts the byte array representation of a hash value into a hash. 
        /// A return value indicates whether the conversion succeeded.
        /// </summary>
        /// <param name="hashValue">A byte array containing a hash value to convert.</param>
        /// <param name="result">When this method returns, contains the hash equivalent
        /// to the hash value in hashValue or null if the conversion failed.</param>
        /// <returns>true if the conversion succeeded; otherwise, false.</returns>
        public static bool TryParse(byte[] hashValue, out T result)
        {
            if (hashValue != null)
            {
                result = CreateUninitializedInstance();

                if (IsHashCodeValid(hashValue, result.HashCodeSize))
                {
                    result.HashValue = hashValue;
                    return true;
                }
            }

            result = null;
            return false;
        }

        /// <summary>
        /// Converts the string representation of a hash code into a hash. 
        /// A return value indicates whether the conversion succeeded.
        /// </summary>
        /// <param name="hashCode">A string containing a hash code to convert.</param>
        /// <param name="result">When this method returns, contains the hash equivalent
        /// to the string in hashCode or null if the conversion failed.</param>
        /// <returns>true if the conversion succeeded; otherwise, false.</returns>
        public static bool TryParse(string hashCode, out T result)
        {
            if (hashCode != null)
            {
                result = CreateUninitializedInstance();

                if (IsHashCodeValid(hashCode, result.HashCodeSize, out hashCode))
                {
                    result.HashCode = hashCode;
                    return true;
                }
            }

            result = null;
            return false;
        }
        #endregion

        #region Hex Conversion
        /// <summary>
        /// Converts a number into it's hex representation.
        /// </summary>
        /// <param name="value">Value to encode in hex</param>
        /// <returns>Single hex character.</returns>
        private static char ToHex(byte value)
        {
            value = (byte)(value & 0xf);

            if (value < 10)
                return (char)(value + '0');

            return (char)(value - 10 + 'a');
        }

        /// <summary>
        /// Converts the specified hex digit to it's numerical representation.
        /// </summary>
        /// <param name="digit">The hex digit to convert.</param>
        /// <returns>Single byte.</returns>
        private static byte FromHex(char digit)
        {
            if (char.IsDigit(digit))
                return (byte)(digit - '0');
            else
                return (byte)(char.ToLower(digit) - 'a' + 10);
        }
        #endregion

        #region IComparable Implementation
        public int CompareTo(object obj)
        {
            if (!(obj is CryptographicHash<T>))
                throw new ArgumentException("obj is not Hash<T>", "obj");

            return CompareTo((CryptographicHash<T>)obj);
        }
        #endregion

        #region IComparable Implementation
        /// <summary>
        /// Compares hash codes and returns an indication of their relative sort order.
        /// </summary>
        /// <param name="other">Another hash code to compare to.</param>
        /// <returns>A signed integer that indicates the relative values of this and other.</returns>
        public int CompareTo(CryptographicHash<T> other)
        {
            return StringComparer.OrdinalIgnoreCase.Compare(HashCode, other.HashCode);
        }
        #endregion

        #region IEquatable Implementation
        /// <summary>
        /// Indicated whether the hash codes are equal.
        /// </summary>
        /// <param name="other">A hash to compare to.</param>
        /// <returns>true if this and other hash code have equal values, otherwise, false.</returns>
        public bool Equals(CryptographicHash<T> other)
        {
            if (ReferenceEquals(other, null))
                return false;

            return StringComparer.OrdinalIgnoreCase.Equals(HashCode, other.HashCode);
        }
        #endregion

        #region Operator Overload
        public static bool operator ==(CryptographicHash<T> x, CryptographicHash<T> y)
        {
            if (ReferenceEquals(x, null))
                return ReferenceEquals(y, null);

            if (ReferenceEquals(y, null))
                return false;

            return x.Equals(y);
        }

        public static bool operator !=(CryptographicHash<T> x, CryptographicHash<T> y)
        {
            return !(x == y);
        }
        #endregion

        #region Hashing
        /// <summary>
        /// Creates an instance of the hash algorithm the type represents.
        /// </summary>
        /// <returns>A new instance of the HashAlgorithm.</returns>
        protected abstract HashAlgorithm CreateHashAlgorithm();

        /// <summary>
        /// Computes the hash code for the specified byte array.
        /// </summary>
        /// <param name="data">The input to compute the hash code for.</param>
        /// <returns>The computed hash code.</returns>
        public static T HashBytes(byte[] data)
        {
            T instance = CreateUninitializedInstance();

            using (HashAlgorithm alg = instance.CreateHashAlgorithm())
                instance.HashValue = alg.ComputeHash(data, 0, data.Length);

            return instance;
        }

        /// <summary>
        /// Computes the hash code for the specified System.IO.Stream object.
        /// </summary>
        /// <param name="stream">The input to compute the hash code for.</param>
        /// <returns>The computed hash code.</returns>
        public static T HashStream(Stream stream)
        {
            T instance = CreateUninitializedInstance();

            using (HashAlgorithm alg = instance.CreateHashAlgorithm())
                instance.HashValue = alg.ComputeHash(stream);

            return instance;
        }

        /// <summary>
        /// Computes the hash code for the specified file.
        /// </summary>
        /// <param name="file">The file path to hash.</param>
        /// <returns>The computed hash code.</returns>
        public static T HashFile(string file)
        {
            using (Stream stream = File.Open(file, FileMode.Open, FileAccess.Read))
                return HashStream(stream);
        }
        #endregion

        #region Object Overrides
        /// <summary>
        /// Returns a string representation of the hash.
        /// </summary>
        /// <returns>A string representation of the value of this hash.</returns>
        public override string ToString()
        {
            return ToString(null);
        }

        /// <summary>
        /// Returns a string representation of the hash according to the provided format specifier.
        /// </summary>
        /// <param name="format">A single format specifier that indicates how to format the value of this hash.
        /// The format parameter can be "D" or "H". If format is null or an empty string (""), "H" is used.</param>
        /// <returns>A string representation of the value of this hash.</returns>
        public string ToString(string format)
        {
            const string invalidFormat = "Invalid hash format specified.";
            const string formatParameter = "format";

            if (format == null || format.Length == 0)
                format = "H";

            if (format.Length != 1)
                throw new ArgumentException(invalidFormat, formatParameter);

            switch (format[0])
            {
                case 'D': //formats the hash code with dash separator every 4 characters
                    char[] hashCode = new char[HashCodeSize + HashCodeSize / 4 - 1];
                    int offset = 0;
                    int separatorIndex = 4;

                    for (int i = 0; i < hashCode.Length; i++)
                    {
                        if (i == separatorIndex)
                        {
                            separatorIndex += 5;
                            offset++;
                            hashCode[i] = '-';
                        }
                        else
                            hashCode[i] = HashCode[i - offset];
                    }
                    return new string(hashCode);
                case 'H':
                    return HashCode;
                default:
                    throw new ArgumentException(invalidFormat, formatParameter);
            }
        }

        /// <summary>
        /// Gets a hash code for the hash code.
        /// </summary>
        /// <returns>A 32-bit signed hash code calculated from the hash code.</returns>
        public override int GetHashCode()
        {
            return StringComparer.OrdinalIgnoreCase.GetHashCode(HashCode);
        }

        /// <summary>
        /// Indicated whether the hash code is equal to the specified object.
        /// </summary>
        /// <param name="other">A object to compare to.</param>
        /// <returns>true if this and other hash code have equal values, otherwise, false.</returns>
        public override bool Equals(object obj)
        {
            if (ReferenceEquals(obj, null))
                return false;

            CryptographicHash<T> y = obj as CryptographicHash<T>;

            if (ReferenceEquals(y, null))
                return false;

            return Equals(y);
        }
        #endregion

        /// <summary>
        /// Creates an uninitialized instance of the class.
        /// </summary>
        private static T CreateUninitializedInstance()
        {
            return (T)FormatterServices.GetUninitializedObject(typeof(T));
        }

        /// <summary>
        /// Gets the hash length in characters.
        /// </summary>
        private static int GetHashCodeSize()
        {
            var instance = CreateUninitializedInstance();

            return instance.HashCodeSize;
        }

        /// <summary>
        /// Converts the hash into a byte array.
        /// </summary>
        /// <returns>A byte array that represents the hash code.</returns>
        public byte[] ToArray()
        {
            return HashValue;
        }
        #endregion
    }
}
