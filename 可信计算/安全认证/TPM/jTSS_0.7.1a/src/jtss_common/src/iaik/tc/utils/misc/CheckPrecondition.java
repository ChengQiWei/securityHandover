/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */

package iaik.tc.utils.misc;


/**
 * This class contains methods that are used to check an validated parameters passed to methods.
 */
public class CheckPrecondition {

	/*************************************************************************************************
	 * This method is used to ensure that a given parameter is not null.
	 */
	public static void notNull(final Object input, final String argName)
		throws IllegalArgumentException
	{
		if (input == null) {
			throw new IllegalArgumentException("Argument '" + ((argName == null) ? "unknown" : argName)
					+ "' must not be null.");
		}
	}


	/*************************************************************************************************
	 * This method is used to ensure that a given parameter is not null.
	 */
	public static void notNegative(final long input, final String argName)
		throws IllegalArgumentException
	{
		if (input < 0) {
			throw new IllegalArgumentException("Argument '" + ((argName == null) ? "unknown" : argName)
					+ "' must not be < 0.");
		}
	}


	/*************************************************************************************************
	 * This method is used to ensure that a given parameter is not null.
	 */
	public static void gtZero(final long input, final String argName) throws IllegalArgumentException
	{
		if (input <= 0) {
			throw new IllegalArgumentException("Argument '" + ((argName == null) ? "unknown" : argName)
					+ "' must not be <= 0.");
		}
	}


	/*************************************************************************************************
	 * This method is used to ensure that a given parameter is less than or equal to the given upper
	 * bound.
	 */
	public static void ltOrEq(final long input, final String argName, final long upperBound)
		throws IllegalArgumentException
	{
		if (input > upperBound) {
			throw new IllegalArgumentException("Argument '" + ((argName == null) ? "unknown" : argName)
					+ "' must less than or equal to " + upperBound + ".");
		}
	}

	
	/*************************************************************************************************
	 * This method is used to ensure that a given parameter is less than or equal to the given upper
	 * bound.
	 */
	public static void gtOrEq(final long input, final String argName, final long lowerBound)
		throws IllegalArgumentException
	{
		if (input < lowerBound) {
			throw new IllegalArgumentException("Argument '" + ((argName == null) ? "unknown" : argName)
					+ "' must greater than or equal to " + lowerBound + ".");
		}
	}


	/*************************************************************************************************
	 * This method is used to ensure that a given parameter is not null.
	 */
	public static void equal(final long input, final long expected, final String argName)
		throws IllegalArgumentException
	{
		if (input != expected) {
			throw new IllegalArgumentException("Argument '" + ((argName == null) ? "unknown" : argName)
					+ "' is not equal to " + expected + ".");
		}
	}


	/*************************************************************************************************
	 * This method is used to ensure that a given parameter is an instance of a given class. This is
	 * useful if the parameter of a method is specified in some generic form (e.g. Interface) but the
	 * actual implementation only works correctly if the supplied parameter is a specific
	 * implementation of the interface.
	 */
	public static void isInstanceOf(Object objToCheck, String objName, Class exptectedType)
	{
		if (!exptectedType.isInstance(objToCheck)) {
			throw new IllegalArgumentException("Argument '" + objName + "' is not an instance of "
					+ exptectedType.getName() + ".");
		}
	}


	/*************************************************************************************************
	 * This method is a variation of {@link CheckPrecondition#isInstanceOf(Object, String, Class)}.
	 * In contrast to the later, this method does not throw an exception is objToCheck is null. It can
	 * be used to check if optional parameters are of a specific type.
	 */
	public static void optionalInstanceOf(Object objToCheck, String objName, Class exptectedType)
	{
		if (objToCheck == null) {
			return;
		}
		isInstanceOf(objToCheck, objName, exptectedType);
	}


	/*************************************************************************************************
	 * This method first checks if objToCheck is not null and then checks if it is an instance of
	 * expectgedType. It effectively combines combines the methods
	 * {@link CheckPrecondition#notNull(Object, String)} and
	 * {@link CheckPrecondition#isInstanceOf(Object, String, Class)}.
	 */
	public static void notNullAndInstanceOf(Object objToCheck, String objName, Class exptectedType)
	{
		notNull(objToCheck, objName);
		isInstanceOf(objToCheck, objName, exptectedType);
	}

}
