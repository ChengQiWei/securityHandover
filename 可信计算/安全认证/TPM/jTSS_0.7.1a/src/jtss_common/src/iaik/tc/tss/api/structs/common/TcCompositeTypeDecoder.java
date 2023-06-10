/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.common;




/**
 * This class extends the basic type decoding class and adds functionality to handle composite types
 * such as TPM_KEY_PARMS. The individual elements of such structs are represented by the fields of
 * the classes that inherit from TcCompositeTypeDecoder. In addition to decoding composite types,
 * this class also supports the construction encoding as raw byte blob of composite types. By using
 * the set methods of the child classes, the elements can be filled with their desired values.
 * Subsequently, the getEncoded method returns a byte blob representing the structures contents.
 * This blob can then be handed to lower layers (TSS).
 */
public abstract class TcCompositeTypeDecoder extends TcBasicTypeDecoder {

	/*************************************************************************************************
	 * Default Constructor. This constructor is used to create an empty instance. The field contents
	 * can then be assigned using the set-methods of the child class. Via the getEncoded method, a byte
	 * blob representation of the data can be obtained.
	 */
	public TcCompositeTypeDecoder()
	{
		super();
	}


	/*************************************************************************************************
	 * This constructor takes a byte data object to be decoded. The initial offset is set to 0.
	 * 
	 * @param data The byte data to be decoded.
	 */
	public TcCompositeTypeDecoder(TcBlobData data)
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
	public TcCompositeTypeDecoder(TcBlobData data, int offset)
	{
		super(data, offset);
		decode();
	}


	/*************************************************************************************************
	 * This constructor takes another composite type object as argument. It is useful if a composite
	 * type contains fields that are not of a primitive type but of a composite type. To decode such a
	 * field, the outer structure crates an instance of the appropriate class and passes the this
	 * pointer to the constructor. The inner class can then obtain the raw data and the current offset
	 * from the outer structure. After decoding of the inner class is complete, the offset of the
	 * outer structure is advanced accordingly. The outer structure can then continue with decoding
	 * without the need to manually correct the current offset. This is illustrated e.g. in the
	 * TcTpmKey.decode method.
	 * 
	 * @param composite outer structure this structure belongs to
	 */
	public TcCompositeTypeDecoder(TcCompositeTypeDecoder composite)
	{
		super(composite.blob_, composite.offset_);
		decode();
		composite.offset_ = offset_;
	}


	/*************************************************************************************************
	 * For debugging purposes, the toString method can be useful to examine the inner state of
	 * composite type objects.
	 */
	public String toString()
	{
		return "toString not implemented";
	}


	/*************************************************************************************************
	 * This method has to be implemented by child classes. The actual decoding of the byte blob is
	 * performed in this method. It is called by the constructor after the byte data blob has been
	 * set.
	 */
	protected abstract void decode();


	/*************************************************************************************************
	 * This method returns the internal state of a type object as a byte blob. The fields a encoded in
	 * big endian byte order (MSB first). Byte packing is done at byte boundaries as specified in the
	 * TCG spec.
	 * 
	 * @return byte blob to be passed to other layers (e.g. TSS)
	 */
	public abstract TcBlobData getEncoded();

}
