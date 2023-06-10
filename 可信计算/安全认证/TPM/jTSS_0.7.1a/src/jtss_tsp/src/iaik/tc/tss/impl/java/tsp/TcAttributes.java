/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tsp;


import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tsp.TcTspException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.tspi.TcIAttributes;
import iaik.tc.utils.logging.Log;
import iaik.tc.utils.misc.Utils;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;

/**
 * This class implements the attribute handling for TSS working objects. The TSS specification
 * defines two basic attribute types: UINT32 attributes and data (byte array) attributes. For both
 * attribute types, generic getter and setter methods are defined ({@link TcIAttributes#setAttribData(long, long, TcBlobData)},
 * {@link TcIAttributes#getAttribData(long, long)},
 * {@link TcIAttributes#setAttribUint32(long, long, long)} and
 * {@link TcIAttributes#getAttribUint32(long, long)}). The first parameter always is the flag and
 * the second one the subFlag. Together they define the attribute to get/set. To allow a more
 * convenient form of implementation, for every flag an own getter and setter method is implemented
 * in the working objects. To be compatible with the generic getter and setter methods defined by
 * the TSS specification, this class provides these generic methods that map incoming calls to the
 * actual getter and setter methods of the working object. To do that, each working object has to
 * register its attribute getter and setter methods together with the corresponding flag value. This
 * is done by implementing the abstract initAttribGetters and initAttribSetters methods.
 */
public abstract class TcAttributes implements TcIAttributes {

	/**
	 * This map holds mappings of flags to UINT32 setter methods.
	 */
	private HashMap attribSettersUINT32_ = new HashMap();

	/**
	 * This map holds mappings of flags to UINT32 getter methods.
	 */
	private HashMap attribGettersUINT32_ = new HashMap();

	/**
	 * This map holds mappings of flags to data setter methods.
	 */
	private HashMap attribSettersData_ = new HashMap();

	/**
	 * This map holds mappings of flags to data getter methods.
	 */
	private HashMap attribGettersData_ = new HashMap();


	/**
	 * The abstract initialization methods (to be implemented by the inheriting working object) are
	 * called to allow the working object to establish the "flag to getter/setter method" mappings.
	 * 
	 */
	public TcAttributes()
	{
		initAttribGetters();
		initAttribSetters();
	}


	/**
	 * This method has to be implemented by the inheriting working object. In this method, the
	 * working object can register its setter method.
	 */
	protected abstract void initAttribSetters();


	/**
	 * This method has to be implemented by the inheriting working object. In this method, the
	 * working object can register its getter method.
	 */
	protected abstract void initAttribGetters();


	/**
	 * This method is used by the working object to register UINT32 setter methods.
	 */
	protected synchronized void addSetterUINT32(long attribFlag, String methodName)
	{
		try {
			Method method = this.getClass().getMethod(methodName, new Class[] { Long.TYPE, Long.TYPE });
			attribSettersUINT32_.put(new Long(attribFlag), method);
		} catch (NoSuchMethodException e) {
			Log.debug("Unable to find UINT32 setter method: " + methodName);
		}
	}


	/**
	 * This method is used by the working object to register UINT32 getter methods.
	 */
	protected synchronized void addGetterUINT32(long attribFlag, String methodName)
	{
		try {
			Method method = this.getClass().getMethod(methodName, new Class[] { Long.TYPE });
			attribGettersUINT32_.put(new Long(attribFlag), method);
		} catch (NoSuchMethodException e) {
			Log.debug("Unable to find UINT32 getter method: " + methodName);
		}
	}


	/**
	 * This method is used by the working object to register data setter methods.
	 */
	protected synchronized void addSetterData(long attribFlag, String methodName)
	{
		try {
			Method method = this.getClass().getMethod(methodName,
					new Class[] { Long.TYPE, TcBlobData.class });
			attribSettersData_.put(new Long(attribFlag), method);
		} catch (NoSuchMethodException e) {
			Log.debug("Unable to find data setter method: " + methodName);
		}
	}


	/**
	 * This method is used by the working object to register data getter methods.
	 */
	protected synchronized void addGetterData(long attribFlag, String methodName)
	{
		try {
			Method method = this.getClass().getMethod(methodName, new Class[] { Long.TYPE });
			attribGettersData_.put(new Long(attribFlag), method);
		} catch (NoSuchMethodException e) {
			Log.debug("Unable to find data getter method: " + methodName);
		}
	}


	/*
	 * (non-Javadoc)
	 * @see iaik.tss.api.tspi.TcIAttributes#getAttribData(long, long)
	 */
	public synchronized TcBlobData getAttribData(long attribFlag, long subFlag) throws TcTssException
	{
		if (!attribGettersData_.containsKey(new Long(attribFlag))) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_FLAG);
		}

		Object methodObj = attribGettersData_.get(new Long(attribFlag));
		if (!(methodObj instanceof Method)) {
			throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR,
					"The attribute getter is not a valid Method object.");
		}

		Method method = (Method) methodObj;

		Object retVal = null;
		try {
			retVal = method.invoke(this, new Object[] { new Long(subFlag) });
		} catch (IllegalAccessException e) {
			throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR, "Getter method ("
					+ method.getName() + ") is not accessible.");
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof TcTssException) {
				throw (TcTssException) e.getTargetException();
			} else {
				throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR,
						"Getter method did throw unknown exception (not a TcTssException)." + Utils.getNL()
								+ e.getTargetException().getMessage());
			}
		}

		if (!(retVal instanceof TcBlobData)) {
			throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR, "The return value received from "
					+ method.getName() + " is not of type TcBlobData.");
		}

		return (TcBlobData) retVal;
	}


	/*
	 * (non-Javadoc)
	 * @see iaik.tss.api.tspi.TcIAttributes#getAttribUint32(long, long)
	 */
	public long getAttribUint32(long attribFlag, long subFlag) throws TcTssException
	{
		if (!attribGettersUINT32_.containsKey(new Long(attribFlag))) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_FLAG);
		}

		Object methodObj = attribGettersUINT32_.get(new Long(attribFlag));
		if (!(methodObj instanceof Method)) {
			throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR,
					"The attribute getter is not a valid Method object.");
		}

		Method method = (Method) methodObj;

		Object retVal = null;
		try {
			retVal = method.invoke(this, new Object[] { new Long(subFlag) });
		} catch (IllegalAccessException e) {
			throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR, "Getter method ("
					+ method.getName() + ") is not accessible.");
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof TcTssException) {
				throw (TcTssException) e.getTargetException();
			} else {
				throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR,
						"Getter method did throw unknown exception (not a TcTssException)." + Utils.getNL()
								+ e.getTargetException().getMessage());
			}
		}

		if (!(retVal instanceof Long)) {
			throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR, "The return value received from "
					+ method.getName() + " is not of type Long.");
		}

		return ((Long) retVal).longValue();
	}


	/*
	 * (non-Javadoc)
	 * @see iaik.tss.api.tspi.TcIAttributes#setAttribData(long, long, iaik.tss.api.structs.TcBlobData)
	 */
	public void setAttribData(long attribFlag, long subFlag, TcBlobData attrib) throws TcTssException
	{
		if (!attribSettersData_.containsKey(new Long(attribFlag))) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_FLAG);
		}

		Object methodObj = attribSettersData_.get(new Long(attribFlag));
		if (!(methodObj instanceof Method)) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
					"The attribute setter is not a valid Method object.");
		}

		Method method = (Method) methodObj;

		try {
			method.invoke(this, new Object[] { new Long(subFlag), attrib });
		} catch (IllegalAccessException e) {
			throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR, "Setter method ("
					+ method.getName() + ") is not accessible.");
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof TcTssException) {
				throw (TcTssException) e.getTargetException();
			} else {
				throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR, "Setter method ("
						+ method.getName() + ") did throw unknown exception (not a TcTssException)."
						+ Utils.getNL() + e.getTargetException().getMessage());
			}
		}
	}


	/*
	 * (non-Javadoc)
	 * @see iaik.tss.api.tspi.TcIAttributes#setAttribUint32(long, long, long)
	 */
	public void setAttribUint32(long attribFlag, long subFlag, long attrib) throws TcTssException
	{
		if (!attribSettersUINT32_.containsKey(new Long(attribFlag))) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_FLAG);
		}

		Object methodObj = attribSettersUINT32_.get(new Long(attribFlag));
		if (!(methodObj instanceof Method)) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
					"The attribute setter is not a valid Method object.");
		}

		Method method = (Method) methodObj;

		try {
			method.invoke(this, new Object[] { new Long(subFlag), new Long(attrib) });
		} catch (IllegalAccessException e) {
			throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR, "Setter method ("
					+ method.getName() + ") is not accessible.");
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof TcTssException) {
				throw (TcTssException) e.getTargetException();
			} else {
				throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR,
						"Setter method did throw unknown exception (not a TcTssException)." + Utils.getNL()
								+ e.getTargetException().getMessage());
			}
		}
	}
}
