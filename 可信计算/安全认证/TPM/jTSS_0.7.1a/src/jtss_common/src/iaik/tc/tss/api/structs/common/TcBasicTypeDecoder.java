/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.common;


import iaik.tc.utils.misc.Utils;
import java.math.BigInteger;

/**
 * This class provides a set of basic decoding methods for simple TCG defined types such as UINT32.
 * The decoding assumes that the data is provided in big endian (MSB first) byte order by lower
 * layers (TSS). Furthermore, it is assumed that structures are packed on byte boundaries. Both
 * assumptions are based on the statements on "Endness of Structures" and "Byte Packing" in the TCG
 * TPM Specification. Instances of this class take a a raw byte data blob with an
 * optional initial offset. By calling the decode methods, the byte data is decoded according to the
 * type of the decode method. The decodeUINT32 method for instance, reads 4 bytes (starting at the
 * current offset), interprets them as a 4 byte integer and returns it. The internal offset is
 * advanced by the size of the decoded type (4 bytes in the case of UNIT32).
 */
public class TcBasicTypeDecoder {

	/**
	 * This field holds the byte data to be decoded.
	 */
	protected final TcBlobData blob_;

	/**
	 * This filed holds the current offset used when decoding the byte data.
	 */
	protected int offset_ = 0;


	/*************************************************************************************************
	 * /* hidden default constructor
	 */
	protected TcBasicTypeDecoder()
	{
		// no data to decode
		blob_ = null;
	}


	/*************************************************************************************************
	 * This constructor takes a byte data object to be decoded. The initial offset is set to 0.
	 * 
	 * @param data The byte data to be decoded.
	 */
	public TcBasicTypeDecoder(final TcBlobData data)
	{
		this(data, 0);
	}


	/*************************************************************************************************
	 * This constructor takes a byte data object to be decoded. The initial offset is set to the
	 * specified one.
	 * 
	 * @param data The byte data to be decoded.
	 * @param offset The initial offset.
	 */
	public TcBasicTypeDecoder(final TcBlobData data, final int offset)
	{
		blob_ = data;
		offset_ = offset;
	}


	/*************************************************************************************************
	 * The decode method can be implemented by child classes. The actual decoding of the data takes
	 * place here.
	 */
	protected void decode()
	{
	}


	/*************************************************************************************************
	 * Precondition check that verifies that the requested amount of data does not exceed the
	 * available amount of data.
	 */
	protected void checkBoundaryPreconditions(int len)
	{
		if (offset_ < 0) {
			throw new IndexOutOfBoundsException("Offset must be greater than 0.");
		}

		if ((offset_ + len) > blob_.getLength()) {
			throw new IndexOutOfBoundsException(
					"Unable to decode requested type. Current offset + type length exceeds data length.");
		}
	}


	/*************************************************************************************************
	 * This method decodes an UINT32 type starting at the current offset. The Value is returned as a
	 * Java long to avoid problems with the signdness of the Java 32bit int type.
	 */
	public long decodeUINT32()
	{
		if (blob_ == null) {
			return 0;
		}
		
		int len = 4;
		checkBoundaryPreconditions(len);

		short[] elements = blob_.getRangeAsShortArray(offset_, len);
		offset_ += len;

		long tmp = 0;
		
		if (blob_.getByteOrder() == TcByteOrder.BYTE_ORDER_BE) {
			tmp |= (byte)elements[0] & 0x00ff;
			tmp <<= 8;
			tmp |= (byte)elements[1] & 0x00ff;
			tmp <<= 8;
			tmp |= (byte)elements[2] & 0x00ff;
			tmp <<= 8;
			tmp |= elements[3] & 0x00ff;
			
		} else {
			tmp |= elements[3] & 0x00ff;
			tmp <<= 8;
			tmp |= elements[2] & 0x00ff;
			tmp <<= 8;
			tmp |= elements[1] & 0x00ff;
			tmp <<= 8;
			tmp |= elements[0] & 0x00ff;
		}
		
		if (tmp < 0) {
			throw new IllegalArgumentException("The decoded value is no legal UINT32 (" + tmp + ").");
		}
		
		
		return tmp;
	}


	/*************************************************************************************************
	 * This method decodes an UINT64 type starting at the current offset. The Value is returned as a
	 * unsigned Java BigInteger.
	 */
	public BigInteger decodeUINT64()
	{
			
		
		if (blob_ == null) {
			return new BigInteger("0");
		}
		
		if (blob_.byteOrder_ != TcByteOrder.BYTE_ORDER_BE)
		 {
			 throw new IllegalArgumentException("Byteorder of given LE UINT64 is not implemented.");
		 }
		
		int len = 8;
		checkBoundaryPreconditions(len);
				
		
		byte[] elements = blob_.getRange(offset_, len);
		offset_ += len;
		
		return new BigInteger(1,elements);
	}

	
	/*************************************************************************************************
	 * This method decodes an UINT16 type starting at the current offset. The Value is returned as a
	 * Java int to avoid problems with the signdness of the Java 16bit int type.
	 */
	public int decodeUINT16()
	{
		if (blob_ == null) {
			return 0;
		}
		
		int len = 2;
		checkBoundaryPreconditions(len);
	
		short[] elements = blob_.getRangeAsShortArray(offset_, len);
		offset_ += len;
	
		int tmp = 0;
		
		if (blob_.getByteOrder() == TcByteOrder.BYTE_ORDER_BE) {
			tmp |= elements[0] & 0x00ff;
			tmp <<= 8;
			tmp |= elements[1] & 0x00ff;
		
		} else {
			tmp |= elements[1] & 0x00ff;
			tmp <<= 8;
			tmp |= elements[0] & 0x00ff;
		}
		
		return tmp;
	}


	/*************************************************************************************************
	 * This method decodes a single byte.
	 */
	public short decodeByte()
	{
		if (blob_ == null) {
			return 0;
		}

		checkBoundaryPreconditions(1);

		short retVal = (short) (blob_.getElement(offset_) & 0xff);
		offset_++;
		return retVal;
	}


	/*************************************************************************************************
	 * This method returns the given number of bytes starting at the current offset.
	 * 
	 * @param numBytes number of bytes to decode
	 */
	public TcBlobData decodeBytes(int numBytes)
	{
		checkBoundaryPreconditions(numBytes);

		if (numBytes < 1) {
			return null;
		}

		byte[] retVal = blob_.getRange(offset_, numBytes);
		offset_ += numBytes;
//		return TcTssStructFactory.newBlobData().initByteArray(retVal);
		return TcBlobData.newByteArray(retVal);
	}


	/*************************************************************************************************
	 * Overloaded method taking a long instead of an int as argument.
	 */
	public TcBlobData decodeBytes(long numBytes)
	{
		return decodeBytes((int) numBytes);
	}


	/*************************************************************************************************
	 * This method decodes a single byte and interprets it as a boolean value.
	 */
	public boolean decodeBoolean()
	{
		return Utils.byteToBoolean((byte)decodeByte());
	}


	/*
	 * convenience methods for types defined in tss_types.h
	 */

	/*************************************************************************************************
	 * This method decodes a TSS_HANDLE.
	 */
	public long decodeTssHandle()
	{
		return decodeUINT32();
	}


	/*************************************************************************************************
	 * This method decodes a TSS_FLAG.
	 */
	public long decodeTssFlag()
	{
		return decodeUINT32();
	}


	/*************************************************************************************************
	 * This method decodes a TSS_RESULT.
	 */
	public long decodeTssResult()
	{
		return decodeUINT32();
	}


	/*************************************************************************************************
	 * This method decodes a TSS_HOBJECT.
	 */
	public long decodeTssHObjet()
	{
		return decodeUINT32();
	}


	/*************************************************************************************************
	 * This method decodes a TSS_HCONTEXT.
	 */
	public long decodeTssHContext()
	{
		return decodeUINT32();
	}


	/*************************************************************************************************
	 * This method decodes a TSS_HPOLICY.
	 */
	public long decodeTssHPolicy()
	{
		return decodeUINT32();
	}


	/*************************************************************************************************
	 * This method decodes a TSS_HTPM.
	 */
	public long decodeTssHTpm()
	{
		return decodeUINT32();
	}


	/*************************************************************************************************
	 * This method decodes a TSS_HKEY.
	 */
	public long decodeTssHKey()
	{
		return decodeUINT32();
	}


	/*************************************************************************************************
	 * This method decodes a TSS_HENC_DATA.
	 */
	public long decodeTssHEncData()
	{
		return decodeUINT32();
	}


	/*************************************************************************************************
	 * This method decodes a TSS_HPCRS.
	 */
	public long decodeTssHPcrs()
	{
		return decodeUINT32();
	}


	/*************************************************************************************************
	 * This method decodes a TSS_HHASH.
	 */
	public long decodeTssHHash()
	{
		return decodeUINT32();
	}


	/*************************************************************************************************
	 * This method decodes a TSS_HPS.
	 */
	public long decodeTssHPS()
	{
		return decodeUINT32();
	}


	/*************************************************************************************************
	 * This method decodes a TSS_EVEN_TYPE.
	 */
	public long decodeTssEvenType()
	{
		return decodeUINT32();
	}


	/*************************************************************************************************
	 * This method decodes a TSS_MIGRATION_SCHEME.
	 */
	public int decodeTssMigrationScheme()
	{
		return decodeUINT16();
	}


	/*************************************************************************************************
	 * This method decodes a TSS_ALGORITHM_ID.
	 */
	public long decodeTssAlgorithmId()
	{
		return decodeUINT32();
	}


	/*************************************************************************************************
	 * This method decodes a TSS_KEY_USAGE_ID.
	 */
	public long decodeTssKeyUsageId()
	{
		return decodeUINT32();
	}


	/*************************************************************************************************
	 * This method decodes a TSS_ENC_SCHEME.
	 */
	public int decodeTssEncScheme()
	{
		return decodeUINT16();
	}


	/*************************************************************************************************
	 * This method decodes a TSS_SIG_SCHEME.
	 */
	public int decodeTssSigScheme()
	{
		return decodeUINT16();
	}


	/*
	 * convenience methods for types defined in tpm.h
	 */

	/*************************************************************************************************
	 * This method decodes a TPM_ENC_SCHEME.
	 */
	public int decodeTpmEncScheme()
	{
		return decodeUINT16();
	}


	/*************************************************************************************************
	 * This method decodes a TPM_SIG_SCHEME.
	 */
	public int decodeTpmSigScheme()
	{
		return decodeUINT16();
	}


	/*************************************************************************************************
	 * This method decodes a TPM_ALGORITHM_ID.
	 */
	public long decodeTpmAlgorithmId()
	{
		return decodeUINT32();
	}


	/*************************************************************************************************
	 * This method decodes a TPM_KEY_USAGE.
	 */
	public int decodeTpmKeyUsage()
	{
		return decodeUINT16();
	}


	/*************************************************************************************************
	 * This method decodes a TPM_KEY_FLAGS.
	 */
	public long decodeTpmKeyFlags()
	{
		return decodeUINT32();
	}


	/*************************************************************************************************
	 * This method decodes a TPM_AUTH_DATA_USAGE.
	 */
	public short decodeTpmAuthDataUsage()
	{
		return decodeBytes(1).asShortArray()[0];
	}
}
