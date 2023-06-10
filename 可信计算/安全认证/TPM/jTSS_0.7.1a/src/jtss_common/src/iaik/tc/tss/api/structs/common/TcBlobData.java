/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.common;


import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.impl.csp.TcBasicCrypto;
import iaik.tc.utils.misc.CheckPrecondition;
import iaik.tc.utils.misc.Utils;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/***************************************************************************************************
 * This class represents a data blob (binary data object) that is received from/passed to the TSS.
 * Passing parameters as simple unsigned byte arrays is a common practice in the TSS APIs. This
 * class provides an abstraction of this byte data objects.
 */
public class TcBlobData {

	/**
	 * Internal byte data.
	 */
	protected byte[] data_ = null;

	/**
	 * The byte order which is assumed when converting types such as int or long to an array of bytes.
	 * The default byte order is big endian (i.e. the byte order used by the TPM).
	 */
	protected byte byteOrder_ = TcByteOrder.TPM_BYTE_ORDER;

	/**
	 * The string encoding that is used by the class when converting a String to an array of bytes.
	 * The default encoding is UTF-16LE (TSS Spec. 1.2, Errata A.23). Note that TSS Spec. 1.1 does not
	 * explicitly specify UTF-16LE for string encoding. The spec only mentions UNICODE without giving
	 * further details.
	 * 
	 * @TSS_V1 24
	 * @TSS_V12 96
	 */
	protected String stringEncoding_ = "UTF-16LE";

	/**
	 * TSS spec. 1.2 (Errata A.19 onwards) states that "The null character SHOULD NOT be included by
	 * default." for TSS_UNICODE strings entered via TSS_SECRET_MODE_POPUP. This behavior is adopted
	 * as default by jTSS not only for secret strings but all strings that are handled by the
	 * TcBlobData class.
	 */
	protected boolean stringIsNullTerminated_ = false;


	/*************************************************************************************************
	 * Protected default constructor. Instances of this class are generated using the struct factory.
	 */
	protected TcBlobData()
	{
	}


	/* -------------------------------------------------------------------------------------------- */
	/* Start of Factory Methods */
	/*
	 * Note: This class is not initialized using constructors (the default constructor is hidden) but
	 * using a set of static factory methods. The rationale for this is that with constructors it is
	 * not possible to explicitly express the type to be initialized (e.g. UINT32). With the factory
	 * methods one is able to clearly express the which to e.g. create an UINT32.
	 */

	/*************************************************************************************************
	 * Initializes the object using the provided short value. This is equivalent to the TSS BYTE (8
	 * bit) data type.
	 * 
	 * @param input Single byte the object is initialized with.
	 * @return this Pointer of the object
	 * 
	 * @throws IllegalArgumentException If negative arguments are supplied, this exception is thrown.
	 */
	public static TcBlobData newBYTE(short input) throws IllegalArgumentException
	{
		return (new TcBlobData()).initBYTE(input);
	}


	/*************************************************************************************************
	 * Initializes the object using the provided boolean value. This is equivalent to the TSS BOOL (8
	 * bit) data type.
	 * 
	 * @param input Single byte the object is initialized with.
	 * @return this Pointer of the object
	 * 
	 * @throws IllegalArgumentException If negative arguments are supplied, this exception is thrown.
	 */
	public static TcBlobData newBOOL(boolean input) throws IllegalArgumentException
	{
		return (new TcBlobData()).initBYTE(Utils.booleanToByte(input));
	}


	/*************************************************************************************************
	 * Initializes the object using the provided int value. Note that only positive int arguments are
	 * accepted. Otherwise an IllegalArgumentException is thrown. This is the way, the UINT16
	 * (unsigned 16 bit integer) specified in the TCG specs, is handled.
	 * 
	 * @param input Single short the object is initialized with.
	 * @return this Pointer of the object
	 * 
	 * @throws IllegalArgumentException If negative arguments are supplied, this exception is thrown.
	 */
	public static TcBlobData newUINT16(int input) throws IllegalArgumentException
	{
		return (new TcBlobData()).initUINT16(input);
	}


	/*************************************************************************************************
	 * Initializes the object using the provided int value. Note that only positive int arguments are
	 * accepted. Otherwise an IllegalArgumentException is thrown. This is the way, the UINT16
	 * (unsigned 16 bit integer) specified in the TCG specs, is handled. This method additionally
	 * allows to specify the byte order used when converting the UINT32 into a byte array.
	 * 
	 * @param input Single short the object is initialized with.
	 * @param byteOrder byte order to be used
	 * @return this Pointer of the object
	 * 
	 * @throws IllegalArgumentException If negative arguments are supplied, this exception is thrown.
	 */
	public static TcBlobData newUINT16(int input, byte byteOrder) throws IllegalArgumentException
	{
		return (new TcBlobData()).initUINT16(input, byteOrder);
	}


	/*************************************************************************************************
	 * Initializes the object using the provided long value. Note that only positive long arguments
	 * are accepted. Otherwise an IllegalArgumentException is thrown. This is the way, the UINT32
	 * (unsigned 32 bit integer) specified in the TCG specs, is handled.
	 * 
	 * @param input Single int the object is initialized with.
	 * @return this Pointer of the object
	 * 
	 * @throws IllegalArgumentException If negative arguments are supplied, this exception is thrown.
	 */
	public static TcBlobData newUINT32(long input) throws IllegalArgumentException
	{
		return (new TcBlobData()).initUINT32(input);
	}


	/**
	 * 
	 * @param input Single BigInteger the object is initialized with.
	 * @return this Pointer of the object
	 * @throws IllegalArgumentException If negative arguments are supplied, this exception is thrown.
	 */
	public static TcBlobData newUINT64(BigInteger input) throws IllegalArgumentException
	{
		return (new TcBlobData()).initUINT64(input);
	}
	
	/*************************************************************************************************
	 * Initializes the object using the provided long value. Note that only positive long arguments
	 * are accepted. Otherwise an IllegalArgumentException is thrown. This is the way, the UINT32
	 * (unsigned 32 bit integer) specified in the TCG specs, is handled. This method additionally
	 * allows to specify the byte order used when converting the UINT32 into a byte array.
	 * 
	 * @param input Single short the object is initialized with.
	 * @param byteOrder byte order to be used
	 * @return this Pointer of the object
	 * 
	 * @throws IllegalArgumentException If negative arguments are supplied, this exception is thrown.
	 */
	public static TcBlobData newUINT32(long input, byte byteOrder) throws IllegalArgumentException
	{
		return (new TcBlobData()).initUINT32(input, byteOrder);
	}


	/*************************************************************************************************
	 * This factory method creates a new blob and initializes it with the given byte array.
	 */
	public static TcBlobData newByteArray(byte[] input)
	{
		return (new TcBlobData()).initByteArray(input);
	}


	/*************************************************************************************************
	 * This factory method creates a new blob and initializes it with the given byte array. This
	 * method copies numBytes from the input array starting at offset.
	 * 
	 * @param input Byte array the object is initialized with.
	 * @param offset the Offset the data copying starts from
	 * @param numBytes the number of bytes copied
	 * @return this Pointer of the new object
	 */
	public static TcBlobData newByteArray(byte[] input, int offset, int numBytes)
	{
		return (new TcBlobData()).initByteArray(input, offset, numBytes);
	}


	/*************************************************************************************************
	 * Initializes the object using the provided String value. The String is parsed into an array of
	 * bytes in accordance with the provided String encoding scheme.
	 * 
	 * @param input String the object is initialized with.
	 * @param addNullTermination If true, a null termination character is appended.
	 * @param stringEncoding The encoding scheme used when parsing the given String into a byte array.
	 * @return this Pointer of the object
	 */
	public static TcBlobData newString(final String input, final boolean addNullTermination,
			String stringEncoding)
	{
		return (new TcBlobData()).initString(input, addNullTermination, stringEncoding);
	}


	/*************************************************************************************************
	 * Initializes the object using the provided String value. This method uses the uses the default
	 * encoding scheme. Note that the TSS spec 1.2 (Errata A.19 onwards) says that the terminating
	 * null character SHOULD NOT be included by default in TSS_UNICODE strings coming from
	 * TSS_SECRET_MODE_POPUP. Based on this statement, probably all passwords should be created
	 * without null termination.
	 * 
	 * @param input String the object is initialized with.
	 * @param addNullTermination If true, a null termination character is appended.
	 * @return this Pointer of the object
	 */
	public static TcBlobData newString(final String input, final boolean addNullTermination)
	{
		return (new TcBlobData()).initString(input, addNullTermination);
	}


	/*************************************************************************************************
	 * Initializes the object using the provided String value.Note that this method uses the default
	 * string encoding and the default null termination behavior.
	 * 
	 * @param input String the object is initialized with.
	 * @return this Pointer of the object
	 * 
	 * @TSS_1_2_EA 230
	 */
	public static TcBlobData newString(final String input)
	{
		return (new TcBlobData()).initString(input);
	}


	/*************************************************************************************************
	 * Initializes the object using the provided String value. As encoding scheme, ASCII is used. No
	 * null termination character is added. This method is a convenience method and is intended to be
	 * used if e.g. the Ownership password has been set using C command line tools which do not use
	 * UNICODE strings. Note that this method uses the default null termination behavior.
	 * 
	 * @param input String the object is initialized with.
	 * @return this Pointer of the object
	 */
	public static TcBlobData newStringASCII(final String input)
	{
		return (new TcBlobData()).initStringASCII(input);
	}


	/*************************************************************************************************
	 * This method takes another TcBlobData object and copies its contents to this object (i.e. Copy
	 * Constructor).
	 * 
	 * @param other Other BlobData object this object is initialized with.
	 * @return this Pointer of the object
	 */
	public static TcBlobData newBlobData(TcBlobData other)
	{
		return (new TcBlobData()).initBlobData(other);
	}


	/* End of Factory Methods */
	/* -------------------------------------------------------------------------------------------- */

	/*************************************************************************************************
	 * This method allows to override the default byte order used when parsing mutli-byte types into a
	 * byte array.
	 * 
	 * @param byteOrder The byte order to the used.
	 */
	public void overrideByteOrder(byte byteOrder)
	{
		byteOrder_ = byteOrder;
	}


	/*************************************************************************************************
	 * This method allows to override the string encoding scheme that is used when interpreting the
	 * data held by the object.
	 * 
	 * @param encoding The string encoding scheme used for interpreting the objects data.
	 */
	public void overrideStringEncoding(String encoding)
	{
		CheckPrecondition.notNull(encoding, "encoding");
		stringEncoding_ = encoding;
	}


	/*************************************************************************************************
	 * This method allows to override the internal flag indicating if the contained string data is
	 * null terminated or not. This method is expected to be rarely used by developers. The only case
	 * where this function might be required is if the objects as initialized with string data using
	 * other methods than the initString methods (e.g. initByteArray). In such a case, this method
	 * allows to define if the binary data (if treated as a string) is null terminated or not.
	 * 
	 * @param isNullTerminated The null termination state for the data.
	 */
	public void overrideStringIsNullTerminated(boolean isNullTerminated)
	{
		stringIsNullTerminated_ = isNullTerminated;
	}


	/*************************************************************************************************
	 * This method returns the byte order used when converting UINT16 and UINT32 types to byte blobs.
	 * 
	 * @return byte order used for UINT16 and UINT32
	 */
	public byte getByteOrder()
	{
		return byteOrder_;
	}


	/*************************************************************************************************
	 * Initializes the object using the provided byte array.
	 * 
	 * @param input Byte array the object is initialized with.
	 * @return this Pointer of the object
	 */
	protected TcBlobData initByteArray(byte[] input)
	{
		data_ = input;
		return this;
	}


	/*************************************************************************************************
	 * Initializes the object using the provided byte array. This method copies numBytes from the
	 * input array starting at offset.
	 * 
	 * @param input Byte array the object is initialized with.
	 * @param offset the Offset the data copying starts from
	 * @param numBytes the number of bytes copied
	 * @return this Pointer of the object
	 */
	protected TcBlobData initByteArray(byte[] input, int offset, int numBytes)
	{
		CheckPrecondition.notNull(input, "input");

		data_ = new byte[numBytes];
		System.arraycopy(input, offset, data_, 0, numBytes);
		return this;
	}


	/*************************************************************************************************
	 * Initializes the object using the provided byte value. This is equivalent to the TCG BYTE (8
	 * bit) data type. Note that the Java byte type is signed while the TSS BYTE type is unsigned.
	 * 
	 * @param input Single byte the object is initialized with.
	 * @return this Pointer of the object
	 */
	protected TcBlobData initBYTE(short input)
	{
		if (input < 0) {
			throw new IllegalArgumentException("Input is out of valid range for type BYTE.");
		}

		data_ = new byte[] { (byte) input };
		return this;
	}


	/*************************************************************************************************
	 * Initializes the object using the provided int value. Note that only positive int arguments are
	 * accepted. Otherwise an IllegalArgumentException is thrown. This is the way, the UINT16
	 * (unsigned 16 bit integer) specified in the TCG specs, is handled.
	 * 
	 * @param input Single short the object is initialized with.
	 * @return this Pointer of the object
	 * 
	 * @throws IllegalArgumentException If negative arguments are supplied, this exception is thrown.
	 */
	protected TcBlobData initUINT16(int input)
	{
		if (input < 0) {
			throw new IllegalArgumentException("Input is out of valid range for type UINT16.");
		}

		data_ = new byte[2];

		if (byteOrder_ == TcByteOrder.BYTE_ORDER_BE) {
			data_[1] = (byte) (input & 0x00ff); // LSB is stored in highest address
			input >>= 8;
			data_[0] = (byte) (input & 0x00ff);

		} else {
			data_[0] = (byte) (input & 0x00ff); // LSB is stored in lowest address (LSB first)
			input >>= 8;
			data_[1] = (byte) (input & 0x00ff);
		}

		return this;
	}


	/*************************************************************************************************
	 * Initializes the object using the provided int value. Note that only positive int arguments are
	 * accepted. Otherwise an IllegalArgumentException is thrown. This is the way, the UINT16
	 * (unsigned 16 bit integer) specified in the TCG specs, is handled. This method additionally
	 * allows to specify the byte order used when converting the UINT32 into a byte array.
	 * 
	 * @param input Single short the object is initialized with.
	 * @param byteOrder byte order to be used
	 * @return this Pointer of the object
	 * 
	 * @throws IllegalArgumentException If negative arguments are supplied, this exception is thrown.
	 */
	protected TcBlobData initUINT16(int input, byte byteOrder) throws IllegalArgumentException
	{
		byteOrder_ = byteOrder;
		return initUINT16(input);
	}


	/*************************************************************************************************
	 * Initializes the object using the provided long value. Note that only positive long arguments
	 * are accepted. Otherwise an IllegalArgumentException is thrown. This is the way, the UINT32
	 * (unsigned 32 bit integer) specified in the TCG specs, is handled.
	 * 
	 * @param input Single int the object is initialized with.
	 * @return this Pointer of the object
	 * 
	 * @throws IllegalArgumentException If negative arguments are supplied, this exception is thrown.
	 */
	protected TcBlobData initUINT32(long input)
	{
		if (input < 0) {
			throw new IllegalArgumentException("Input is out of valid range for type UINT32.");
		}

		data_ = new byte[4];

		if (byteOrder_ == TcByteOrder.BYTE_ORDER_BE) {
			data_[3] = (byte) (input & 0x000000ff); // LSB is stored in highest address
			input >>= 8;
			data_[2] = (byte) (input & 0x000000ff);
			input >>= 8;
			data_[1] = (byte) (input & 0x000000ff);
			input >>= 8;
			data_[0] = (byte) (input & 0x000000ff);

		} else {
			data_[0] = (byte) (input & 0x000000ff); // LSB is stored in lowest address (LSB first)
			input >>= 8;
			data_[1] = (byte) (input & 0x000000ff);
			input >>= 8;
			data_[2] = (byte) (input & 0x000000ff);
			input >>= 8;
			data_[3] = (byte) (input & 0x000000ff);
		}

		return this;
	}

	
	/**
	 * Initializes the object using the provided BigInteger value.
	 * This handles the UINT64 Type of the TPM.
	 * @param input a 64bit unsigned integer held within a Biginteger
	 * @return this pointer of the object
	 */
	protected TcBlobData initUINT64(BigInteger input)
	{
					
		 if (input.signum() < 0) {
		 	throw new IllegalArgumentException("Input is out of valid range for type UINT32.");
		 }
		 if (byteOrder_ != TcByteOrder.BYTE_ORDER_BE)
		 {
			 throw new IllegalArgumentException("Byteorder of given LE UINT64 is not implemented.");
		 }
		 
		  byte[] elements = input.toByteArray();
	 
		 data_ = new byte[8]; //initialise to zero

		 for (int i=0; i!=elements.length; i++)
		 {
			 data_[data_.length-elements.length+i]=elements[i];
		 }
	
		return this;
	}

	
	/*************************************************************************************************
	 * Initializes the object using the provided long value. Note that only positive long arguments
	 * are accepted. Otherwise an IllegalArgumentException is thrown. This is the way, the UINT32
	 * (unsigned 32 bit integer) specified in the TCG specs, is handled. This method additionally
	 * allows to specify the byte order used when converting the UINT32 into a byte array.
	 * 
	 * @param input Single short the object is initialized with.
	 * @param byteOrder byte order to be used
	 * @return this Pointer of the object
	 * 
	 * @throws IllegalArgumentException If negative arguments are supplied, this exception is thrown.
	 */
	protected TcBlobData initUINT32(long input, byte byteOrder) throws IllegalArgumentException
	{
		byteOrder_ = byteOrder;
		return initUINT32(input);
	}


	/*************************************************************************************************
	 * Initializes the object using the provided String value. The String is parsed into an array of
	 * bytes in accordance with the provided String encoding scheme.
	 * 
	 * @param input String the object is initialized with.
	 * @param addNullTermination If true, a null termination character is appended.
	 * @param stringEncoding The encoding scheme used when parsing the given String into a byte array.
	 * @return this Pointer of the object
	 */
	protected TcBlobData initString(final String input, final boolean addNullTermination,
			String stringEncoding)
	{
		CheckPrecondition.notNull(input, "input");
		CheckPrecondition.notNull(stringEncoding, "stringEncoding");

		stringEncoding_ = stringEncoding;
		StringBuffer data = new StringBuffer(input);

		if (addNullTermination) {
			stringIsNullTerminated_ = true;
			data.append('\0');
		} else {
			stringIsNullTerminated_ = false;
		}

		try {
			data_ = data.toString().getBytes(stringEncoding_);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e.getMessage());
		}

		return this;
	}


	/*************************************************************************************************
	 * Initializes the object using the provided String value. This method uses the uses the default
	 * encoding scheme. Note that the TSS spec 1.2 (Errata A.19 onwards) says that the terminating
	 * null character SHOULD NOT be included by default in TSS_UNICODE strings coming from
	 * TSS_SECRET_MODE_POPUP. Based on this statement, probably all passwords should be created
	 * without null termination.
	 * 
	 * @param input String the object is initialized with.
	 * @param addNullTermination If true, a null termination character is appended.
	 * @return this Pointer of the object
	 */
	protected TcBlobData initString(final String input, final boolean addNullTermination)
	{
		return initString(input, addNullTermination, stringEncoding_);
	}


	/*************************************************************************************************
	 * Initializes the object using the provided String value. This method appends a null termination
	 * character and uses the default encoding scheme. Note that this method uses the default string
	 * encoding and the default null termination behavior.
	 * 
	 * @param input String the object is initialized with.
	 * @return this Pointer of the object
	 * 
	 * @TSS_v12 230
	 */
	protected TcBlobData initString(final String input)
	{
		return initString(input, stringIsNullTerminated_, stringEncoding_);
	}


	/*************************************************************************************************
	 * Initializes the object using the provided String value. As encoding scheme, ASCII is used. No
	 * null termination character is added. This method is a convenience method and is intended to be
	 * used if e.g. the Ownership password has been set using C command line tools which do not use
	 * UNICODE strings. Note that this method uses the default null termination behavior.
	 * 
	 * @param input String the object is initialized with.
	 * @return this Pointer of the object
	 */
	public TcBlobData initStringASCII(final String input)
	{
		return initString(input, stringIsNullTerminated_, "ASCII");
	}


	/*************************************************************************************************
	 * This method takes another TcBlobData object and copies its contents to this object (i.e. Copy
	 * Constructor).
	 * 
	 * @param other Other BlobData object this object is initialized with.
	 * @return this Pointer of the object
	 */
	protected TcBlobData initBlobData(TcBlobData other)
	{
		CheckPrecondition.notNull(other, "other");
		CheckPrecondition.notNull(other.data_, "other.data_");

		data_ = new byte[other.getLength()];
		System.arraycopy(other.data_, 0, data_, 0, other.getLength());
		byteOrder_ = other.byteOrder_;
		stringEncoding_ = other.stringEncoding_;
		stringIsNullTerminated_ = other.stringIsNullTerminated_;

		return this;
	}


	/*************************************************************************************************
	 * This method is used to append binary data to the current binary data block.
	 * 
	 * @param dataToAppend data to be appended to the current block
	 */
	public void append(final TcBlobData dataToAppend)
	{
		CheckPrecondition.notNull(dataToAppend, "dataToAppend");
		CheckPrecondition.notNull(dataToAppend.data_, "dataToAppend.data_");
		checkIsInitialized();

		byte[] combined = new byte[getLength() + dataToAppend.getLength()];

		System.arraycopy(data_, 0, combined, 0, getLength());
		System.arraycopy(dataToAppend.data_, 0, combined, getLength(), dataToAppend.getLength());

		data_ = combined;
	}


	/*************************************************************************************************
	 * This method is used to prepend binary data to the current binary data block.
	 * 
	 * @param dataToPrepend data to be prepended to the current block
	 */
	public void prepend(final TcBlobData dataToPrepend)
	{
		CheckPrecondition.notNull(dataToPrepend, "dataToPrepend");
		CheckPrecondition.notNull(dataToPrepend.data_, "dataToPrepend.data_");
		checkIsInitialized();

		byte[] combined = new byte[getLength() + dataToPrepend.getLength()];

		System.arraycopy(dataToPrepend.data_, 0, combined, 0, dataToPrepend.getLength());
		System.arraycopy(data_, 0, combined, dataToPrepend.getLength(), getLength());

		data_ = combined;
	}


	/*************************************************************************************************
	 * This method returns the byte value at the given position.
	 * 
	 * @param index the index of the element to be returned.
	 * @return the value at index
	 */
	public byte getElement(final int index)
	{
		checkIsInitialized();
		if (index < 0 || index >= getLength()) {
			throw new IndexOutOfBoundsException();
		}

		return data_[index];
	}


	/*************************************************************************************************
	 * This method returns the length of the binary data.
	 * 
	 * @return the length of the binary data
	 */
	public int getLength()
	{
		if (data_ == null) {
			return 0;
		}
		return data_.length;
	}


	/*************************************************************************************************
	 * This method returns the length of the binary data.
	 * 
	 * @return the length of the binary data
	 */
	public long getLengthAsLong()
	{
		return (long) getLength();
	}


	/*************************************************************************************************
	 * This method returns a specified range of elements.
	 * 
	 * @param index first element to be returned
	 * @param numElements number of elements to be returned
	 * @return byte array containing the specified range of elements (note: array elements are signed)
	 */
	public byte[] getRange(final int index, final int numElements)
	{
		checkIsInitialized();

		if (numElements < 1) {
			throw new IllegalArgumentException("numElements must be greater than 0");
		}
		if (index < 0 || index + numElements > getLength()) {
			throw new IndexOutOfBoundsException();
		}

		byte[] retVal = new byte[numElements];

		System.arraycopy(data_, index, retVal, 0, numElements);

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a specified range of elements. In contrast to the getRange method, this
	 * method returns a short array where each (short) element holds an unsigned byte (in contrast to
	 * signed byte in case of the getRange method). I.e. only the range from 0 to 255 of every short
	 * element is actually used. This method is provided for convenience.
	 * 
	 * @param index first element to be returned
	 * @param numElements number of elements to be returned
	 * @return short array containing the specified range of elements (note: array elements are
	 *         unsigned)
	 */
	public short[] getRangeAsShortArray(final int index, final int numElements)
	{
		return Utils.byteArrayToShortArray(getRange(index, numElements));
	}


	/*************************************************************************************************
	 * This method returns the entire binary data as a byte array. Note that in contrast to the
	 * original C data where the individual array elements are unsigned bytes, the Java byte type is
	 * always signed.
	 * 
	 * @return byte array containing the binary data.
	 */
	public byte[] asByteArray()
	{
		if (data_ == null) {
			return null;
		} else {
			return data_;
		}
	}


	/*************************************************************************************************
	 * This method returns the entire binary data as a short array. This method returns the same
	 * content as the asByteArray method but encoded the individual bytes as shorts. The shorts only
	 * contain non negative values. This representation does not require the user to take care of the
	 * signedness of the byte data type in Java. The returned array contains the same data (regarding
	 * signedness) as the actual unsigned char array in C. This method is provided for convenience.
	 * 
	 * @return short array containing the binary data.
	 */
	public short[] asShortArray()
	{
		if (data_ == null) {
			return null;
		} else {
			return Utils.byteArrayToShortArray(data_);
		}
	}


	/*************************************************************************************************
	 * This method allows to substitute a contiguous range of bytes in the byte blob.
	 * 
	 * @param offset The offset where the substitution starts.
	 * @param data The data to be substituted into the blob.
	 */
	public void substBytes(final int offset, final byte[] data)
	{
		if (offset + data.length > getLength()) {
			throw new IllegalArgumentException("Offset + data.length exceed the length of the blob");
		}

		for (int i = 0; i < data.length; i++) {
			data_[offset + i] = data[i];
		}
	}


	/*************************************************************************************************
	 * This method returns the SHA-1 digest of the contained binary data.
	 * 
	 * @return SHA-1 digest of the contained binary data
	 * @throws NoSuchAlgorithmException
	 */
	public TcBlobData sha1()
	{
		checkIsInitialized();
		TcBlobData retVal = new TcBlobData();
		retVal.initByteArray(TcBasicCrypto.sha1(data_));
		return retVal;
	}


	/*************************************************************************************************
	 * This method returns the HmacSha1 digest of the object's data using the given HMAC key.
	 * 
	 * @param key The key used for the HMAC calculation.
	 * @return The HmacSha1 digest of the data.
	 * @throws TcTssException This exception is thrown if the provided key is invalid.
	 */
	public TcBlobData hmacSha1(TcBlobData key)
	{
		CheckPrecondition.notNull(key, "key");
		checkIsInitialized();
		CheckPrecondition.gtZero(key.getLength(), "key length");

		byte[] retValBytes = TcBasicCrypto.hmacSha1(asByteArray(), key.asByteArray());
		return TcBlobData.newByteArray(retValBytes);
	}


	/*************************************************************************************************
	 * This method returns the object's data in XOR encrypted form using the provided key.
	 */
	public TcBlobData xor(TcBlobData key)
	{
		CheckPrecondition.notNull(key, "key");
		checkIsInitialized();

		byte[] retValBytes = TcBasicCrypto.xor(data_, key.asByteArray());
		return TcBlobData.newByteArray(retValBytes);
	}

	/*************************************************************************************************
	 * Flushes the internal buffer by filling it with <tt>0</tt>. Use this for
	 * <code>TcBlobData</code> instances that represent passwords to clear the
	 * password from memory.
	 */
	public void flush()
	{
		checkIsInitialized();
		for (int i = 0; i < data_.length; i++)
		{
			data_[i] = 0;
		}
	}

	/*************************************************************************************************
	 * This method checks if two objects are equal. It compares the entire internal state of the
	 * objects and not only the binary data.
	 * 
	 * @return true if the two objects have the same internal state
	 */
	public boolean equals(final Object obj)
	{
		if (!(obj instanceof TcBlobData)) {
			return false;
		}

		TcBlobData other = (TcBlobData) obj;

		// common checks (data independent)
		if (byteOrder_ != other.byteOrder_)
			return false;
		if (!stringEncoding_.equals(other.stringEncoding_))
			return false;
		if (stringIsNullTerminated_ != other.stringIsNullTerminated_)
			return false;

		// checks depending on data == null or != null
		if (data_ != null && other.data_ != null) {
			return Arrays.equals(data_, other.data_);
		} else if (data_ == null && other.data_ == null) {
			return true;
		} else {
			// one of the two is null and the other one is not
			return false;
		}
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#hashCode()
	 */
	public int hashCode()
	{
		return (int) new TcBasicTypeDecoder(sha1()).decodeUINT32();
	}


	/*************************************************************************************************
	 * This method returns a clone of the object.
	 */
	public Object clone()
	{
		byte[] dataCopy = new byte[data_.length];
		System.arraycopy(data_, 0, dataCopy, 0, data_.length);
		TcBlobData retVal = (new TcBlobData()).initByteArray(dataCopy);
		retVal.byteOrder_ = byteOrder_;
		retVal.stringEncoding_ = stringEncoding_;
		retVal.stringIsNullTerminated_ = stringIsNullTerminated_;
		return retVal;
	}


	/*************************************************************************************************
	 * Returns a hex string representation of the object's binary data.
	 */
	public String toHexString()
	{
		if (data_ == null) {
			return new String("data is null");
		}
		return Utils.byteArrayToHexString(data_, " ", 16);
	}


	public String toHexStringNoWrap()
	{
		if (data_ == null) {
			return new String("data is null");
		}
		return Utils.byteArrayToHexString(data_, " ", 0);
	}

	
	/*************************************************************************************************
	 * Checks if the object is already initialized.
	 */
	protected void checkIsInitialized()
	{
		if (data_ == null) {
			throw new IllegalStateException("Object was not initialized.");
		}
	}


	/*************************************************************************************************
	 * This method returns true if the contained string data is null terminated, false otherwise. Note
	 * that this method is only guaranteed to return correct values if the string was initialized
	 * using one of the initString methods. If the string was set any other way (e.g. as a byte array)
	 * incorrect values might be reported by this method.
	 */
	public boolean stringIsNullTerminated()
	{
		return stringIsNullTerminated_;
	}


	/*************************************************************************************************
	 * This method appends or removes the null termination character of the contained data based on
	 * the current state of the stringIsNullTerminated_ flag.
	 */
	public void toggleNullTermination()
	{
		if (stringIsNullTerminated_) {

			byte[] tmp = null;
			if (data_[data_.length - 1] == 0 && data_[data_.length - 2] == 0) {
				// string seems to have a 2 byte null termination
				tmp = new byte[data_.length - 2];
			} else if (data_[data_.length - 1] == 0 && data_[data_.length - 2] != 0) {
				// string seems to have a 1 byte null termination
				tmp = new byte[data_.length - 1];
			} else {
				throw new IllegalStateException(
						"Unable to remove null termination - no null termination found.");
			}

			System.arraycopy(data_, 0, tmp, 0, tmp.length);
			data_ = tmp;
			stringIsNullTerminated_ = false;
		} else {
			initString(toString(), true);
			stringIsNullTerminated_ = true;
		}
	}


	/*************************************************************************************************
	 * This method overwrites the data held internally by the object with all zeros. This can be
	 * useful if the blob held sensitive information that is no longer used.
	 */
	public void invalidateContent()
	{
		for (int i = 0; i < data_.length; i++) {
			data_[i] = 0;
		}
	}


	/*************************************************************************************************
	 * Returns a string representation of the object's binary data. The string is encoded according to
	 * the internal stringEncoding.
	 */
	public String toString()
	{
		checkIsInitialized();

		try {
			return new String(data_, stringEncoding_);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e.getMessage());
		}
	}


	/*************************************************************************************************
	 * Returns a string representation of the object's binary data. The string is assumed to be ASCII
	 * encoded.
	 */
	public String toStringASCII()
	{
		checkIsInitialized();

		try {
			return new String(data_, "ASCII");
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e.getMessage());
		}
	}
}
