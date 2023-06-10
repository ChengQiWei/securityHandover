/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tsp;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.utils.misc.CheckPrecondition;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

public class TcPolicyPasswortPopup implements ActionListener {

	protected JPasswordField pwdPassword_;

	protected JPasswordField pwdPasswordRepeat_;

	protected JCheckBox chkNullTermination_;

	protected JButton btnOk_;

	protected JButton btnCancel_;

	protected JLabel lblMsg_;

	protected TcBlobData passwordBlob_ = null;

	protected JFrame frame_;

	boolean showPasswordRepeat_;


	/*************************************************************************************************
	 * TSP password popup window constructor.
	 * 
	 * @param popupString String to be displayed on the popup window.
	 * @param showPasswordRepeat Determines if two fields to enter the password are shown. If true,
	 *          the first password and the repeated second password are checked for equality.
	 */
	protected TcPolicyPasswortPopup(TcBlobData popupString, boolean showPasswordRepeat)
	{
		CheckPrecondition.notNull(popupString, "popupString");

		showPasswordRepeat_ = showPasswordRepeat;

		frame_ = new JFrame();
		
		JDialog dialog = new JDialog(frame_, "TSP Password Dialog", true);
		JPanel panel_ = new JPanel(new GridBagLayout());
		GridBagConstraints grid = new GridBagConstraints();

		// padding
		grid.ipadx = 10;
		grid.ipady = 10;

		// popup string
		grid.gridy = 0;
		grid.gridx = 0;
		grid.gridwidth = 2;
		JLabel popupStringLabel = new JLabel(popupString.toString());
		panel_.add(popupStringLabel, grid);

		// additional message (e.g. if passwords do not match)
		grid.gridy++;
		grid.gridx = 0;
		grid.gridwidth = 2;
		lblMsg_ = new JLabel(" ");
		panel_.add(lblMsg_, grid);

		// first password field
		grid.gridy++;
		grid.gridx = 0;
		grid.gridwidth = 1;
		JLabel textArea = new JLabel("password: ");
		panel_.add(textArea, grid);
		grid.gridx = 1;
		pwdPassword_ = new JPasswordField(20);
		grid.ipadx = 0;
		grid.ipady = 0;
		panel_.add(pwdPassword_, grid);
		grid.ipadx = 10;
		grid.ipady = 10;

		// 2nd password field (password repeat)
		if (showPasswordRepeat_) {
			grid.gridy++;
			grid.gridx = 0;
			JLabel textArea2 = new JLabel("password (repeat): ");
			panel_.add(textArea2, grid);
			grid.gridx = 1;
			pwdPasswordRepeat_ = new JPasswordField(20);
			grid.ipadx = 0;
			grid.ipady = 0;
			panel_.add(pwdPasswordRepeat_, grid);
			grid.ipadx = 10;
			grid.ipady = 10;
		}

		// null termination check-box
		grid.gridy++;
		grid.gridx = 0;
		grid.gridwidth = 2;
		chkNullTermination_ = new JCheckBox("include null termination in password hash");
		chkNullTermination_.addActionListener(this);
		panel_.add(chkNullTermination_, grid);

		// OK button
		grid.gridy++;
		grid.gridx = 0;
		grid.gridwidth = 1;
		btnOk_ = new JButton("OK");
		btnOk_.addActionListener(this);
		panel_.add(btnOk_, grid);

		// cancel button
		grid.gridx = 1;
		btnCancel_ = new JButton("Cancel");
		btnCancel_.addActionListener(this);
		panel_.add(btnCancel_, grid);

		// dialog setup
		dialog.setContentPane(panel_);
		dialog.pack();
		// Java 1.3 compatible frame centering
		dialog.setLocation(Toolkit.getDefaultToolkit().getScreenSize().width / 2 - dialog.getWidth()
				/ 2, Toolkit.getDefaultToolkit().getScreenSize().height / 2 - dialog.getHeight() / 2);
		dialog.setSize(dialog.getWidth() + 10, dialog.getHeight() + 10);
		dialog.setResizable(false);
		dialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
		dialog.setVisible(true);
	}

	


	/*************************************************************************************************
	 * Dialog event handling.
	 */
	public void actionPerformed(ActionEvent evt)
	{
		if (evt.getSource() == btnOk_) {
			String password = new String(pwdPassword_.getPassword());

			if (showPasswordRepeat_) {
				String passwordRepeat = new String(pwdPasswordRepeat_.getPassword());
				if (!password.equals(passwordRepeat)) {
					pwdPassword_.setText("");
					pwdPasswordRepeat_.setText("");
					lblMsg_.setForeground(new Color(255, 0, 0));
					lblMsg_.setText("Passwords did not match. Please try again!");
					return;
				}
			}

			passwordBlob_ = TcBlobData.newString(password, chkNullTermination_.isSelected());
						
			password=""; //FIXXME: proper destruction of string or avoid it completely. 
						
			
			frame_.hide();
			frame_.dispose();

		} else if (evt.getSource() == btnCancel_) {
			passwordBlob_ = null;
			frame_.hide();
			frame_.dispose();
		}
	}


	/*************************************************************************************************
	 * This method returns the password that was entered by the user. If the cancel button was
	 * pressed, null is returned.
	 */
	protected TcBlobData getPasword()
	{
		return passwordBlob_;
	}
}
