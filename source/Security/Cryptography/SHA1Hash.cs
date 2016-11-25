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
    /// <summary>
    /// The SHA1Hash value type represents an SHA256 hash code.
    /// </summary>
    [Serializable]
    public sealed class SHA1Hash : CryptographicHash<SHA1Hash>
    {
        /// <summary>
        /// Initialize the SHA1Hash from a string.
        /// </summary>
        /// <param name="hash">The hash code.</param>
        public SHA1Hash(string hashCode)
            : base(hashCode)
        {

        }

        /// <summary>
        /// Initializes the SHA1Hash from an array of bytes.
        /// </summary>
        /// <param name="bytes">An array of bytes which represent a packed hash code.</param>
        public SHA1Hash(byte[] hashValue)
            : base(hashValue)
        { }

        /// <summary>
        /// Gets the expected hash code size.
        /// </summary>
        public override int HashCodeSize
        {
            get
            {
                return 40;
            }
        }

        /// <summary>
        /// Creates an instance of the hash algorithm the type represents.
        /// </summary>
        /// <returns>A new instance of the HashAlgorithm.</returns>
        protected override HashAlgorithm CreateHashAlgorithm()
        {
            return SHA1Managed.Create();
        }
    }
}
