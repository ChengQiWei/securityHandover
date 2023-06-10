/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */

package iaik.tc.utils.cmdline;


import iaik.tc.utils.misc.Utils;

import java.util.Iterator;
import java.util.TreeMap;

public class SubCommandParser extends CommonParser {

	/**
	 * Map holding the parameters.
	 */
	protected TreeMap subCommands_ = new TreeMap();

	/*************************************************************************************************
	 * This method parses the given argument array. It basically takes a look at the first item and
	 * checks if it is a valid sub-command. If that is the case, it obtains the parameter parser of
	 * this sub-command and passes the remaining arguments to this parser. After the parameter parser
	 * has finished (and no exception has been thrown), the application corresponding to the
	 * sub-command is started.
	 */
	public void parse(String args[]) throws IllegalArgumentException, CommandlineException
	{
		if (args.length == 0) {
			throw new IllegalArgumentException("No sub-command given.");
		}

		String subCommandKey = args[0];
		if (subCommands_.containsKey(subCommandKey)) {

			SubCommand subCmd = (SubCommand) subCommands_.get(subCommandKey);
			ParamParser paramParser = subCmd.getParamParser();

			try {
				paramParser.parse(args, 1);
				subCmd.run(paramParser);
			} catch (IllegalArgumentException e) {
				System.out.println("");
				paramParser.printUsage();
				System.out.println("");
				System.out.println(e.getMessage());
				System.out.println("");
				System.exit(-1);
			}
		} else {
			throw new IllegalArgumentException("Unknown sub-command given.");
		}
	}


	/*************************************************************************************************
	 * This method is used to add a new parameter that should be handled by the parser.
	 *
	 * @param subCmd new command line parameter
	 */
	public void addSubCmd(SubCommand subCmd)
	{
		subCommands_.put(subCmd.getKey(), subCmd);

		if (subCmd.getKey().length() > maxKeyLen_) {
			maxKeyLen_ = subCmd.getKey().length();
		}
	}


	/*************************************************************************************************
	 * This method prints a usage message to standard out.
	 *
	 */
	public void printUsage()
	{
		StringBuffer output = new StringBuffer();

		Iterator it = subCommands_.keySet().iterator();
		while (it.hasNext()) {
			String key = (String) it.next();
			SubCommand subCmd = (SubCommand) subCommands_.get(key);

			StringBuffer sb = new StringBuffer("  ");
			sb.append(key);
			sb.append(getWhitespaces(maxKeyLen_ - subCmd.getKey().length()));
			sb.append(" ... ");
			int descStartPos = sb.length();
			sb.append(subCmd.getDescription());
			sb.append(Utils.getNL());

			sb = wrapString(sb, descStartPos);

			output.append(sb);
		}

		System.out.println(output);
	}

}
