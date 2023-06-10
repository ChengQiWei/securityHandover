/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */

package iaik.tc.utils.cmdline;

import iaik.tc.utils.misc.Utils;


/**
 * This class contains common methods for all parser classes.
 */
public abstract class CommonParser {

	/**
	 * Whitespace string used for padding.
	 */
	protected static final String paddingString_ = "                                                                                           ";
	/**
	 * This field holds the max. string length of all the keys (displayed as part of the usage
	 * message). The value of this field is used to do whitespace padding for proper alignment.
	 */
	protected int maxKeyLen_ = 0;
	/**
	 * This field holds the value defining the maximum number
	 */
	protected int maxCharsPerLine_ = 80;


	/**
	 * This method returns a String with the requested number of whitespace characters.
	 */
	protected String getWhitespaces(int num)
	{
		if (num > paddingString_.length()) {
			return paddingString_;
		}
		return paddingString_.substring(0, num);
	}
	
	/**
	 * This method wraps the given StringBuffer content at maxCharsPerLine. The wrapped
	 * lines are alignment at alignmentPos. The only exception is the first line which
	 * is allowed to consume the full width of the line.
	 */
	protected StringBuffer wrapString(StringBuffer sb, int alignmentPos)
	{
		if (sb.length() > maxCharsPerLine_) {
			StringBuffer tmp = new StringBuffer();

			int endPos = sb.toString().indexOf(" ", maxCharsPerLine_);
			if (endPos < 0) {
				endPos = sb.toString().length();
			}
			tmp.append(sb.substring(0, endPos)); // first part using full length of line
			sb.delete(0, endPos);

			for (int i = 1;; i++) {
				endPos = sb.toString().indexOf(" ", maxCharsPerLine_ - alignmentPos);

				if (endPos > 0) {
					tmp.append(Utils.getNL() + getWhitespaces(alignmentPos)
							+ sb.substring(0, endPos).trim());
					sb.delete(0, endPos);
				} else {
					String line = Utils.getNL() + getWhitespaces(alignmentPos) + sb.substring(0).trim()
							+ Utils.getNL();
					if (line.trim().length() > 0) {
						tmp.append(line);
					}
					break;
				}
			}
			sb = tmp;
		}
		return sb;
	}
}
