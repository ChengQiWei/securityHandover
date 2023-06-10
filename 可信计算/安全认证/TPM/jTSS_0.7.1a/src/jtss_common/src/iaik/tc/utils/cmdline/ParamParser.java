/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */

package iaik.tc.utils.cmdline;


import iaik.tc.utils.misc.Utils;

import java.util.Iterator;
import java.util.TreeMap;

/**
 * This class parses the command line configuration options. The developer can add a set of
 * parameters which are parsed by the this class. The parsed values are then made accessible via
 * getter methods.
 */
public class ParamParser extends CommonParser {

	/**
	 * Map holding the parameters.
	 */
	protected TreeMap parameters_ = new TreeMap();

	/**
	 * This field holds the max. string length of all the dummy values (displayed as part of the usage
	 * message). The value of this field is used to do whitespace padding for proper alignment.
	 */
	protected int maxDummyValueLen_ = 0;


	/*************************************************************************************************
	 * Default constructor.
	 */
	public ParamParser()
	{
	}


	/*************************************************************************************************
	 * This method is used to add a new parameter that should be handled by the parser.
	 * 
	 * @param param new command line parameter
	 */
	public void addParam(Param param)
	{
		parameters_.put(param.getKey(), param);

		if (param.getDummyValue().length() > maxDummyValueLen_) {
			maxDummyValueLen_ = param.getDummyValue().length();
		}

		if (param.getKey().length() > maxKeyLen_) {
			maxKeyLen_ = param.getKey().length();
		}
	}


	/*************************************************************************************************
	 * This method parses the the given command line arguments.
	 * 
	 * @param args The command line arguments to be parsed.
	 * @throws IllegalArgumentException
	 */
	public void parse(String[] args) throws IllegalArgumentException
	{
		parse(args, 0);
	}


	/*************************************************************************************************
	 * This method parses the the given command line arguments.
	 * 
	 * @param args The command line arguments to be parsed.
	 * @param offset This defines an offset where to start parsing the args parameter.
	 * @throws IllegalArgumentException
	 */
	public void parse(String[] args, int offset) throws IllegalArgumentException
	{
		// get the key-value pairs from the args array and set the values in the parameters_ data
		// structure

		for (int i = offset; i < args.length; i++) {
			String key = (String) args[i];
			if (parameters_.containsKey(key)) {
				// key was found - next item should be the value
				Param param = ((Param) parameters_.get(key));
				param.setKeyPresent(true);
				i++;
				if (i < args.length) {
					String value = (String) args[i];
					if (parameters_.containsKey(value)) {
						// The value item also is a key. That means that the last key was given without
						// providing a value.
						i--;
					} else {
						param.setValue(value);
						param.setValuePresent(true);
					}
				}
			} else {
				System.out.println("Ignoring unexpected element: " + key);
			}
		}

		// check if all required parameters are present
		Iterator it = parameters_.keySet().iterator();
		while (it.hasNext()) {
			String key = (String) it.next();
			Param param = (Param) parameters_.get(key);

			if (param.isRequired()) {
				if (!param.isKeyPresent()) {
					String msg = "Parameter Error: The required parameter '" + key + "' was not set.";
					throw new IllegalArgumentException(msg);
				}
				if (param.isValueRequired() && !param.isValuePresent()) {
					String msg = "Parameter Error: No value given for required parameter '" + key + "'.";
					throw new IllegalArgumentException(msg);
				}
			} else {
				// parameter is optional
				if (param.isKeyPresent()) {
					if (param.isValueRequired() && !param.isValuePresent()) {
						// optional parameter is present but no value was given (but value is required)
						String msg = "Parameter Error: Optional parameter '" + key
								+ "' was given but without value.";
						msg += Utils.getNL();
						msg += "This parameter requires a value. Either specify a value or totally omit the optional parameter.";
						throw new IllegalArgumentException(msg);
					}
				}
			}

			// set default value for parameter
			if (!param.isValuePresent()) {
				param.setValue(param.getDefaultValue());
			}
		}
	}


	/*************************************************************************************************
	 * This method returns the corresponding value for the given key.
	 * 
	 * @param key
	 * @return value for given key
	 */
	public String getValue(String key)
	{
		Param param = (Param) parameters_.get(key);

		if (param == null) {
			return null;
		} else {
			return param.getValue();
		}
	}


	/*************************************************************************************************
	 * This method returns the default value for the given key.
	 * 
	 * @param key
	 * @return the default value
	 */
	public String getDefaultValue(String key)
	{
		Param param = (Param) parameters_.get(key);
		return param.getDefaultValue();
	}


	/*************************************************************************************************
	 * This method returns true if the given key is present (i.e. the given key was specified by the
	 * user on the command line).
	 * 
	 * @param key
	 * @return presence status
	 */
	public boolean isPresent(String key)
	{
		Param param = (Param) parameters_.get(key);

		if (param == null) {
			return false;
		} else {
			return param.isKeyPresent();
		}
	}


	/*************************************************************************************************
	 * This method prints the usage message of the application. The message is assembled from the
	 * individual parts of the command line parameters.
	 */
	public void printUsage()
	{
		Iterator it = parameters_.keySet().iterator();
		StringBuffer requiredParams = new StringBuffer();
		StringBuffer optionalParams = new StringBuffer();
		while (it.hasNext()) {
			String key = (String) it.next();
			Param param = (Param) parameters_.get(key);

			StringBuffer sb = new StringBuffer();
			sb.append("  ");
			sb.append(param.getKey());
			sb.append(getWhitespaces(maxKeyLen_ - param.getKey().length()));
			sb.append(" ");
			sb.append(param.getDummyValue());
			sb.append(getWhitespaces(maxDummyValueLen_ - param.getDummyValue().length()));
			sb.append(" ... ");
			int descStartPos = sb.length();
			if (param.getDescription() != null) {
				sb.append(param.getDescription());
			} else {
				sb.append("no description available");
			}
			String[] legals = param.getLegalValues();
			if (legals != null && legals.length > 0) {
				sb.append(" (legal values: ");
				for (int i = 0; i < legals.length; i++) {
					sb.append((String) legals[i]);
					if (i < legals.length - 1) {
						sb.append(", ");
					}
				}
				sb.append(")");
			}

			if (param.getDefaultValue() != null) {
				sb.append(" (default: ");
				sb.append(param.getDefaultValue());
				sb.append(")");
			}

			sb.append(Utils.getNL());

			// if the line length exceeds a predefined value, the lines are going to be wrapped

			sb = wrapString(sb, descStartPos);

			if (param.isRequired()) {
				requiredParams.append(sb);
			} else {
				optionalParams.append(sb);
			}
		}

		if (requiredParams.length() > 0) {
			System.out.println("required parameters:");
			System.out.println(requiredParams.toString());
		}

		if (optionalParams.length() > 0) {
			System.out.println("optional parameters:");
			System.out.println(optionalParams.toString());
		}
	}
}
