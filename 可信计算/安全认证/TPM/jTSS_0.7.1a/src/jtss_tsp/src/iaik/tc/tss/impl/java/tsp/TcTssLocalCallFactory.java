/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tsp;

import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcTssAbstractFactory;
import iaik.tc.tss.impl.java.tsp.tcsbinding.local.TcTcsBindingLocal;

/**
 * This factory provides the Context object when using Local Bindings. These are good for testing or when the overhead
 * of SOAP libraries is to be avoided. 
 */
public class TcTssLocalCallFactory extends TcTssAbstractFactory {

	public TcIContext newContextObject() throws TcTssException
	{
		TcTcsBindingLocal binding = new TcTcsBindingLocal();
		return new TcContext(binding);
	}
}
