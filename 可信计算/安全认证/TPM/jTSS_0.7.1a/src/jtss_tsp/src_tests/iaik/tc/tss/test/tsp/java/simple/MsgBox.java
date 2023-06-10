package iaik.tc.tss.test.tsp.java.simple;

import java.awt.*;
import java.awt.event.*;
import java.util.Vector;

public class MsgBox extends Dialog implements ActionListener {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private Button ok, can;
	public boolean isOk = false;

	/**
	 * @param frame
	 *            parent frame
	 * @param msg
	 *            message to be displayed
	 * @param okcan
	 *            true : ok cancel buttons, false : ok button only
	 */
	MsgBox(Frame frame, String msg, boolean okcan) {
		super(frame, "Message", true);
		setLayout(new BorderLayout());
		add("Center", new Label(msg));
		addOKCancelPanel(okcan);
		createFrame();
		pack();
		setVisible(true);
	}

	/**
	 * @param frame
	 *            parent frame
	 * @param msg1
	 *            first line to be displayed
	 * @param msg2
	 *            second line to be displayed
	 * @param msg3
	 *            third line to be displayed
	 * @param okcan
	 *            true : ok cancel buttons, false : ok button only
	 */
	MsgBox(Frame frame, String msg1, String msg2, String msg3, boolean okcan) {
		super(frame, frame.getTitle());
		setModal(true);
		GridLayout layout = new GridLayout();
		layout.setRows(4);
		layout.setColumns(1);
		setLayout(layout);
		add("Center", new Label(msg1));
		add("Center", new Label(msg2));
		add("Center", new Label(msg3));
		addOKCancelPanel(okcan);
		createFrame();
		pack();
		setVisible(true);
	}

	MsgBox(Frame frame, String msg1, Vector<String> msgs, boolean okcan) {
		super(frame, frame.getTitle());
		setModal(true);
		BorderLayout layout = new BorderLayout();
		setLayout(layout);
		add(new Label(msg1), "North");

		StringBuffer buffer = new StringBuffer();
		int longestLine = 0;
		for (String msg : msgs) {
			buffer.append(msg);
			if (msg.length() > longestLine) {
				longestLine = msg.length();
			}
		}

		int rows = msgs.size();
		int columns = longestLine;
		TextArea area = new TextArea(buffer.toString(), rows, columns, TextArea.SCROLLBARS_NONE);
		area.setEditable(false);
		area.setFont(new Font("Monospaced", Font.PLAIN, 12));
		add(area, "Center");
		addOKCancelPanel(okcan);
		createFrame();
		pack();
		setVisible(true);

	}

	MsgBox(Frame frame, String msg) {
		this(frame, msg, false);
	}

	void addOKCancelPanel(boolean okcan) {
		Panel p = new Panel();
		p.setLayout(new FlowLayout());
		createOKButton(p);
		if (okcan == true)
			createCancelButton(p);
		add("South", p);
	}

	void createOKButton(Panel p) {
		p.add(ok = new Button("OK"));
		ok.addActionListener(this);
	}

	void createCancelButton(Panel p) {
		p.add(can = new Button("Cancel"));
		can.addActionListener(this);
	}

	void createFrame() {
		Dimension d = getToolkit().getScreenSize();
		setLocation(d.width / 3, d.height / 3);
	}

	public void actionPerformed(ActionEvent ae) {
		if (ae.getSource() == ok) {
			isOk = true;
			setVisible(false);
		} else if (ae.getSource() == can) {
			setVisible(false);
		}
	}
}
