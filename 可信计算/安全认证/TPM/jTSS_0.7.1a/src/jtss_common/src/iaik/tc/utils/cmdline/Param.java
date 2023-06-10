/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */

package iaik.tc.utils.cmdline;


import iaik.tc.utils.misc.Utils;

/**
 * This class holds all information relevant for an individual command line parameter. That includes
 * e.g. the key of the parameter, if it is required or optional or legal values.
 */
public class Param {

	/**
	 * This field holds the key of the parameter.
	 */
	protected String key_ = null;

	/**
	 * This field holds a dummy value of the parameter which is displayed next to the key as part of
	 * the usage message.
	 */
	protected String dummyValue_ = null;

	/**
	 * This field holds the value assigned to the parameter.
	 */
	protected String value_ = null;

	/**
	 * This field holds the default value for this parameter as specified by the developer.
	 */
	protected String defaultValue_ = null;

	/**
	 * This field holds a set of legal values for the parameter. If it is empty, the values a user can
	 * specify are not restricted.
	 */
	protected String[] legalValues_ = null;

	/**
	 * This field holds the description of the parameter as displayed as part of the usage message.
	 */
	protected String description_ = null;

	/**
	 * This field represents if the key was set by the user or if it was omitted.
	 */
	protected boolean keyPresent_ = false;

	/**
	 * This field represents if the value was set by the user or if it was omitted.
	 */
	protected boolean valuePresent_ = false;

	/**
	 * This field determines if the parameter is required or optional. Flags for required parameters
	 * start with REQ_, flags for optional parameters start with OPT_.
	 */
	protected byte required_ = OPT_KEY;

	/**
	 * This flag means that the key of the parameter is required.
	 */
	public static byte REQ_KEY = 0x01;

	/**
	 * This flag means that both, key and value, are required.
	 */
	public static byte REQ_BOTH = 0x02;

	/**
	 * This flag means the key is optional.
	 */
	public static byte OPT_KEY = 0x11;

	/**
	 * This flag means that the key is optional. If the key is specified by the user, also a value has
	 * to be given.
	 */
	public static byte OPT_BOTH = 0x12;


	/*************************************************************************************************
	 * Constructor.
	 */
	public Param(String key, String dummyValue, byte required)
	{
		key_ = key;
		dummyValue_ = dummyValue;
		required_ = required;
	}


	/*************************************************************************************************
	 * Constructor.
	 */
	public Param(String key, String dummyValue, byte required, String description)
	{
		this(key, dummyValue, required);
		description_ = description;
	}


	/*************************************************************************************************
	 * Constructor.
	 */
	public Param(String key, String dummyValue, byte required, String description, String defaultValue)
	{
		this(key, dummyValue, required, description);
		defaultValue_ = defaultValue;
	}


	/*************************************************************************************************
	 * Constructor.
	 */
	public Param(String key, String dummyValue, byte required, String description,
			String defaultValue, String[] legalValues)
	{
		this(key, dummyValue, required, description, defaultValue);
		legalValues_ = legalValues;

	}


	/*************************************************************************************************
	 * Returns the description field.
	 * 
	 * @return the description
	 */
	public String getDescription()
	{
		return description_;
	}


	/*************************************************************************************************
	 * Sets the description field.
	 * 
	 * @param description the description to set
	 */
	public void setDescription(String description)
	{
		description_ = description;
	}


	/*************************************************************************************************
	 * Returns the key field.
	 * 
	 * @return the key
	 */
	public String getKey()
	{
		return key_;
	}


	/*************************************************************************************************
	 * Sets the key field.
	 * 
	 * @param key the key to set
	 */
	public void setKey(String key)
	{
		key_ = key;
	}


	/*************************************************************************************************
	 * Returns the legalValues field.
	 * 
	 * @return the legalValues
	 */
	public String[] getLegalValues()
	{
		return legalValues_;
	}


	/*************************************************************************************************
	 * Sets the legalValues field.
	 * 
	 * @param legalValues the legalValues to set
	 */
	public void setLegalValues(String[] legalValues)
	{
		legalValues_ = legalValues;
	}


	/*************************************************************************************************
	 * This method returns true if the parameter (or more precisely it key of the parameter) is
	 * required, false otherwise.
	 */
	public boolean isRequired()
	{
		return (required_ == REQ_KEY || required_ == REQ_BOTH);
	}


	/*************************************************************************************************
	 * This method returns true if a value (and not only a key) is required, false otherwise.
	 */
	public boolean isValueRequired()
	{
		return (required_ == REQ_BOTH || required_ == OPT_BOTH);
	}


	/*************************************************************************************************
	 * Sets the required field.
	 * 
	 * @param required the required to set
	 */
	public void setRequired(byte required)
	{
		required_ = required;
	}


	/*************************************************************************************************
	 * Returns the value field.
	 * 
	 * @return the value
	 */
	public String getValue()
	{
		return value_;
	}


	/*************************************************************************************************
	 * Sets the Value field. It checks if the given values is acceptable (i.e. if it is part of the
	 * legalValues field). If legalValues is empty (or not set), all values will be accepted.
	 * 
	 * @param value the value to set
	 */
	public void setValue(String value) throws IllegalArgumentException
	{
		// there is nothing to set anyway
		if (value == null) {
			return;
		}

		// check if the given value is part of the set of legal values

		if (legalValues_ != null && legalValues_.length > 0) {
			boolean found = false;
			for (int i = 0; i < legalValues_.length; i++) {
				if (legalValues_[i].toLowerCase().equals(value.toLowerCase())) {
					value = legalValues_[i]; // use the notation specified by the developer
					found = true;
					break;
				}
			}

			if (!found) {
				StringBuffer msg = new StringBuffer();
				msg.append("Parameter Error: Illegal value '" + value + "' for parameter " + getKey());
				msg.append(Utils.getNL());
				msg.append("                 Legal values are: ");
				for (int i = 0; i < legalValues_.length; i++) {
					msg.append(legalValues_[i]);
					if (i < legalValues_.length - 1) {
						msg.append(", ");
					}
				}
				msg.append(Utils.getNL());
				throw new IllegalArgumentException(msg.toString());
			}
		}

		value_ = value;
	}


	/*************************************************************************************************
	 * Returns the defaultValue field.
	 * 
	 * @return the defaultValue
	 */
	public String getDefaultValue()
	{
		return defaultValue_;
	}


	/*************************************************************************************************
	 * Sets the defaultValue field.
	 * 
	 * @param defaultValue the defaultValue to set
	 */
	public void setDefaultValue(String defaultValue)
	{
		defaultValue_ = defaultValue;
	}


	/*************************************************************************************************
	 * Returns if the key is present (i.e. specified by the user) or not.
	 */
	public boolean isKeyPresent()
	{
		return keyPresent_;
	}


	/*************************************************************************************************
	 * Returns if a value is present (i.e. specified by the user) or not.
	 */
	public boolean isValuePresent()
	{
		return valuePresent_;
	}


	/*************************************************************************************************
	 * Sets the present field for the key.
	 */
	public void setKeyPresent(boolean present)
	{
		keyPresent_ = present;
	}


	/*************************************************************************************************
	 * Sets the present field for the value.
	 */
	public void setValuePresent(boolean present)
	{
		valuePresent_ = present;
	}


	/*************************************************************************************************
	 * Returns the dummyValue field.
	 * 
	 * @return the dummyValue
	 */
	public String getDummyValue()
	{
		return dummyValue_;
	}


	/*************************************************************************************************
	 * Sets the dummyValue field.
	 * 
	 * @param dummyValue the dummyValue to set
	 */
	public void setDummyValue(String dummyValue)
	{
		dummyValue_ = dummyValue;
	}

}
