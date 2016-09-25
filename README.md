CryptographicHash Base Class
=======

Cryptographic hashing is crucial for security, indexing or comparing data, creating checksums and countless other purposes. You can compute a data hash by using HashAlgorithm.ComputeHash, which returns a byte hash value. I have created a CryptographicHash abstract base class which consumes this value and allows for parsing, formatting, validation, comparisons, and sorting for all major .NET hashing algorithms.

The underlying cryptographic hash is stored in a private field:

    /// <summary>
    /// Defines the underlying hash code this instance represents.
    /// </summary>
    private string HashCode;

Using a string to contain the hash value enables easy ordinal case-insensitive comparison and hash code generating:

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

    /// <summary>
    /// Compares hash codes and returns an indication of their relative sort order.
    /// </summary>
    /// <param name="other">Another hash code to compare to.</param>
    /// <returns>A signed integer that indicates the relative values of this and other.</returns>
    public int CompareTo(CryptographicHash<T> other)
    {
        return StringComparer.OrdinalIgnoreCase.Compare(HashCode, other.HashCode);
    }

    /// <summary>
    /// Gets a hash code for the hash code.
    /// </summary>
    /// <returns>A 32-bit signed hash code calculated from the hash code.</returns>
    public override int GetHashCode()
    {
        return StringComparer.OrdinalIgnoreCase.GetHashCode(HashCode);
    }

The binary hash value is obtained through a private property which packs the hash code by calling the CryptographicHash.ToArray method and unpacks the hash code from the appropriate constructor.

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

I have defined an abstract method named CreateHashAlgorithm that each hashing algorithm class implements to return the HashAlgorithm that type represents:

    /// <summary>
    /// Creates an instance of the hash algorithm the type represents.
    /// </summary>
    /// <returns>A new instance of the HashAlgorithm.</returns>
    protected override HashAlgorithm CreateHashAlgorithm()
    {
        return MD5CryptoServiceProvider.Create();
    }

This allowed me to create static methods (HashBytes, HashStream, HashFile) for hashing:

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

Each class which inherits the CryptographicHash class receives the static hashing methods to create hashes of the underlying HashAlgorithm type:

    MD5Hash md5_data_hash = MD5Hash.HashBytes(new byte[] { ... });
    SHA256Hash sha256_data_hash = SHA256Hash.HashBytes(new byte[] { ... });

There are also two static TryParse methods to safely validate and create instances:

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

Functionality is wrapped and reused inside the base class enabling simple hash definition classes:

    /// <summary>
    /// The SHA256Hash value type represents an SHA256 hash code.
    /// </summary>
    [Serializable]
    public sealed class SHA256Hash : CryptographicHash<SHA256Hash>
    {
        /// <summary>
        /// Initialize the SHA256Hash from a string.
        /// </summary>
        /// <param name="hash">The hash code.</param>
        public SHA256Hash(string hashCode)
            : base(hashCode)
        {
    
        }
    
        /// <summary>
        /// Initializes the SHA256Hash from an array of bytes.
        /// </summary>
        /// <param name="bytes">An array of bytes which represent a packed hash code.</param>
        public SHA256Hash(byte[] hashValue)
            : base(hashValue)
        { }
    
        /// <summary>
        /// Gets the expected hash code size.
        /// </summary>
        public override int HashCodeSize
        {
            get
            {
                return 64;
            }
        }
    
        /// <summary>
        /// Creates an instance of the hash algorithm the type represents.
        /// </summary>
        /// <returns>A new instance of the HashAlgorithm.</returns>
        protected override HashAlgorithm CreateHashAlgorithm()
        {
            return SHA256Managed.Create();
        }
    }
