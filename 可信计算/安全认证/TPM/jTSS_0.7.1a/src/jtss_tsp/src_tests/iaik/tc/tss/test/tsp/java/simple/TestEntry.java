/*
 * Copyright (C) 2010 IAIK, Graz University of Technology
 * author: Josef Sabongui
 */

package iaik.tc.tss.test.tsp.java.simple;

public class TestEntry {
	public SimpleTest test = null;
	public String info = null;

	TestEntry(SimpleTest test, String info) {
		this.test = test;
		this.info = info;
	}
}