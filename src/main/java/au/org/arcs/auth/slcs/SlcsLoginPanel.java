package au.org.arcs.auth.slcs;

import java.util.Map;

import javax.swing.JPanel;

import au.org.arcs.auth.shibboleth.CredentialManager;
import au.org.arcs.auth.shibboleth.IdpObject;
import au.org.arcs.auth.shibboleth.ShibbolethClient;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.RowSpec;
import com.jgoodies.forms.factories.FormFactory;
import javax.swing.JLabel;
import javax.swing.JComboBox;
import javax.swing.JTextField;

public class SlcsLoginPanel extends JPanel implements CredentialManager, IdpObject {
	private JLabel lblIdp;
	private JLabel lblIdpUsername;
	private JLabel lblIdpPassword;
	private JComboBox comboBox;
	private JTextField textField;
	private JTextField textField_1;

	/**
	 * Create the panel.
	 */
	public SlcsLoginPanel() {
		setLayout(new FormLayout(new ColumnSpec[] {
				FormFactory.RELATED_GAP_COLSPEC,
				FormFactory.DEFAULT_COLSPEC,
				FormFactory.RELATED_GAP_COLSPEC,
				ColumnSpec.decode("default:grow"),
				FormFactory.RELATED_GAP_COLSPEC,},
			new RowSpec[] {
				FormFactory.RELATED_GAP_ROWSPEC,
				FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC,
				FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC,
				FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC,}));
		add(getLblIdp(), "2, 2, right, default");
		add(getComboBox(), "4, 2, fill, default");
		add(getLblIdpUsername(), "2, 4, right, default");
		add(getTextField(), "4, 4, fill, default");
		add(getLblIdpPassword(), "2, 6, right, default");
		add(getTextField_1(), "4, 6, fill, default");

	}

	public String get_password() {
		// TODO Auto-generated method stub
		return null;
	}

	public String get_username() {
		// TODO Auto-generated method stub
		return null;
	}

	public void prompt(ShibbolethClient shibboleth) {
		// TODO Auto-generated method stub
		
	}

	public void set_title(String title) {
		// TODO Auto-generated method stub
		
	}

	public String get_idp() {
		// TODO Auto-generated method stub
		return null;
	}

	public void set_idps(Map idps) {
		// TODO Auto-generated method stub
		
	}

	private JLabel getLblIdp() {
		if (lblIdp == null) {
			lblIdp = new JLabel("Idp");
		}
		return lblIdp;
	}
	private JLabel getLblIdpUsername() {
		if (lblIdpUsername == null) {
			lblIdpUsername = new JLabel("Idp username");
		}
		return lblIdpUsername;
	}
	private JLabel getLblIdpPassword() {
		if (lblIdpPassword == null) {
			lblIdpPassword = new JLabel("Idp password");
		}
		return lblIdpPassword;
	}
	private JComboBox getComboBox() {
		if (comboBox == null) {
			comboBox = new JComboBox();
		}
		return comboBox;
	}
	private JTextField getTextField() {
		if (textField == null) {
			textField = new JTextField();
			textField.setColumns(10);
		}
		return textField;
	}
	private JTextField getTextField_1() {
		if (textField_1 == null) {
			textField_1 = new JTextField();
			textField_1.setColumns(10);
		}
		return textField_1;
	}
}
