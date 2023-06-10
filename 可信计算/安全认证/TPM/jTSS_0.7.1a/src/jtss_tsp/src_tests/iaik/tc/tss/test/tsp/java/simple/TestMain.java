/*
 * Copyright (C) 2010 IAIK, Graz University of Technology
 * author: Josef Sabongui
 */

package iaik.tc.tss.test.tsp.java.simple;

import java.awt.Button;
import java.awt.Dimension;
import java.awt.Frame;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;


public class TestMain extends Frame implements ActionListener {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private static final String EXIT = "Quit";

	private Closer closer;

	private Map<Button, SimpleTest> buttonMap = new HashMap<Button, SimpleTest>();
	private Button exitButton;

	TestMain(Vector<TestEntry> tests) {
		super("jTSS examples");

		int count = tests.size() + 1;
		setLayout(new GridLayout(count,1));

		for (TestEntry entry : tests) {
			Button button = new Button(entry.info);
			button.addActionListener(this);
			add(button);
			buttonMap.put(button, entry.test);
		}

		exitButton = new Button(EXIT);
		exitButton.addActionListener(this);
		add(exitButton);

		closer = new Closer();
		addWindowListener(closer);
		Dimension d = getToolkit().getScreenSize();
		setLocation(d.width / 3, d.height / 3);
		pack();
		setVisible(true);
	}

	public void actionPerformed(ActionEvent ae) {
		if (buttonMap.containsKey(ae.getSource())) {
			SimpleTest test = buttonMap.get(ae.getSource());
			test.runTest();
		} else if (ae.getSource() == exitButton) {
			System.exit(0);
		}
	}


	class Closer extends WindowAdapter {
		public void windowClosing(WindowEvent e) {
			System.exit(0);
		}
	}


	public static void main(String argv[]) {

		Vector<TestEntry> tests = new Vector<TestEntry>();
		tests.addElement(new TestEntry(
				new TestManufacturerVersion(), "Get Version and Manufacturer"));
		tests.addElement(new TestEntry(
				new TestReadPcrs(), "Read PCRs values"));
		tests.addElement(new TestEntry(
				new TestTpmFlags(), "Read the currently set TPM flags"));


		tests.addElement(new TestEntry(
				new TestWinDenyCommand(), "Tests if Windows blocks TPM commands"));
		

		new TestMain(tests);
	}

}
