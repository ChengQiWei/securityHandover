/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tsp;

import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.impl.java.tsp.TcContext;
import iaik.tc.tss.impl.java.tsp.tcsbinding.soapservice.TcTcsBindingSoap;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcTssAbstractFactory;

public class TcTssSOAPCallFactory  extends TcTssAbstractFactory {

	public TcIContext newContextObject() throws TcTssException
	{
		TcTcsBindingSoap binding_soap = new TcTcsBindingSoap();
		return new TcContext(binding_soap);
	}
}
