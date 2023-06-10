/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Michael Steurer
 */

package iaik.tc.tss.impl.java.tsp.tcsbinding.soapservice;

import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;

import java.rmi.RemoteException;
import java.util.HashMap;
import java.util.Map;

public class ConvertRemoteExceptions {
	public static void convertTcTcsException(RemoteException e)
			throws TcTcsException {

		Map<String, String> header = convertToMap(e.getLocalizedMessage());

		// for(String a:header.keySet()) {
		// System.out.println(a + ": " + header.get(a));
		// }

		Long errCode;
		String message;

		try {
			errCode = new Long(Integer.parseInt(header.get(
					"error code (without layer)").substring(2), 16));
			message = header.get("additional info");
		} catch (NullPointerException e1) { // the specific items could not be
											// found
			return;
		}

		if (header.containsKey("iaik.tc.tss.api.exceptions.tcs.TcTcsException")) {
			throw new TcTcsException(errCode, message);
		}

		// if(header.containsKey("iaik.tc.tss.api.exceptions.tcs.TcTpmException"))
		// {
		// throw new TcTpmException(e.);
		// }
	}

	public static void convertTcTddlException(RemoteException e)
			throws TcTddlException {

		Map<String, String> header = convertToMap(e.getLocalizedMessage());

		Long errCode;
		String message;

		try {
			errCode = new Long(Integer.parseInt(header.get(
					"error code (without layer)").substring(2), 16));
			message = header.get("additional info");
		} catch (NullPointerException e1) { // the specific items could not be
											// found
			return;
		}

		if (header
				.containsKey("iaik.tc.tss.api.exceptions.tcs.TcTddlException")) {
			throw new TcTddlException(errCode, message);
		}
	}

	public static void convertTcTpmException(RemoteException e)
			throws TcTpmException {

		Map<String, String> header = convertToMap(e.getLocalizedMessage());

		Long errCode;
		String message;

		try {
			errCode = new Long(Integer.parseInt(header.get(
					"error code (without layer)").substring(2), 16));
			message = header.get("additional info");
		} catch (NullPointerException e1) {
			return;
		}

		if (header.containsKey("iaik.tc.tss.api.exceptions.tcs.TcTpmException")) {
			throw new TcTpmException(errCode, message);
		}
	}

	private static Map convertToMap(String message) {
		Map<String, String> header = new HashMap<String, String>();
		for (String a : message.split("\n")) {
			if (a.split(":").length == 2) {
				header.put((a.split(":")[0]).trim(), (a.split(":")[1]).trim());
			} else {
				header.put((a.split(":")[0]).trim(), "");
			}
		}
		return header;
	}
}