package grith.gsindl;

import grisu.jcommons.interfaces.SlcsListener;
import grith.sibboleth.ShibLoginPanel;
import grith.sibboleth.Shibboleth;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;


public class SLCSLoginDialog extends JDialog implements SlcsListener {

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		try {

			Shibboleth.initDefaultSecurityProvider();

			SLCSLoginDialog dialog = new SLCSLoginDialog(
			"https://slcs1.arcs.org.au/SLCS/login");
			dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
			dialog.setVisible(true);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private final JPanel contentPanel = new JPanel();

	private ShibLoginPanel shibLoginPanel;

	private SLCS slcs = null;

	/**
	 * Create the dialog.
	 */
	public SLCSLoginDialog(String url) {
		setBounds(100, 100, 450, 300);
		getContentPane().setLayout(new BorderLayout());
		contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		getContentPane().add(contentPanel, BorderLayout.CENTER);
		contentPanel.setLayout(new BorderLayout(0, 0));
		{
			shibLoginPanel = new ShibLoginPanel(url, true);
			shibLoginPanel.refreshIdpList();
			slcs = new SLCS(shibLoginPanel);
			slcs.addSlcsListener(this);
			contentPanel.add(shibLoginPanel, BorderLayout.CENTER);
		}
		{
			JPanel buttonPane = new JPanel();
			buttonPane.setLayout(new FlowLayout(FlowLayout.RIGHT));
			getContentPane().add(buttonPane, BorderLayout.SOUTH);
			{
				JButton okButton = new JButton("OK");
				okButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {

						shibLoginPanel.login();

					}
				});
				okButton.setActionCommand("OK");
				buttonPane.add(okButton);
				getRootPane().setDefaultButton(okButton);
			}
			{
				JButton cancelButton = new JButton("Cancel");
				cancelButton.setActionCommand("Cancel");
				buttonPane.add(cancelButton);
			}
		}
	}

	public void slcsLoginComplete(X509Certificate cert, PrivateKey pk) {

		System.out.println(cert.toString());
	}

	public void slcsLoginFailed(String message, Exception optionalException) {

		System.out.println(message);

	}

}
