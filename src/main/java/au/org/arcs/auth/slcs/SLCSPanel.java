package au.org.arcs.auth.slcs;

import java.util.Map;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

import au.org.arcs.auth.shibboleth.IdpObject;

import com.jgoodies.forms.factories.FormFactory;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.RowSpec;

public class SLCSPanel extends JPanel implements IdpObject {
	
	private JTextField textField;
	private JPasswordField passwordField;
	private JTextField textField_1;
	private JTextField textField_2;
	
	private DefaultComboBoxModel idpModel = new DefaultComboBoxModel();
	
	private SLCS slcs = new SLCS();

	/**
	 * Create the panel.
	 */
	public SLCSPanel() {
		setLayout(new FormLayout(new ColumnSpec[] {
				FormFactory.RELATED_GAP_COLSPEC, FormFactory.DEFAULT_COLSPEC,
				FormFactory.RELATED_GAP_COLSPEC,
				ColumnSpec.decode("default:grow"),
				FormFactory.RELATED_GAP_COLSPEC, }, new RowSpec[] {
				FormFactory.RELATED_GAP_ROWSPEC, FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC, FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC, FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC, FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC, FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC, FormFactory.DEFAULT_ROWSPEC,
				FormFactory.RELATED_GAP_ROWSPEC, }));
		{
			JLabel label = new JLabel("New label");
			add(label, "2, 2, right, default");
		}
		{
			JComboBox comboBox = new JComboBox(idpModel);
			add(comboBox, "4, 2, fill, default");
		}
		{
			JLabel label = new JLabel("New label");
			add(label, "2, 4");
		}
		{
			textField = new JTextField();
			add(textField, "4, 4, fill, default");
			textField.setColumns(10);
		}
		{
			JLabel label = new JLabel("New label");
			add(label, "2, 6, right, default");
		}
		{
			passwordField = new JPasswordField();
			add(passwordField, "4, 6, fill, default");
		}
		{
			JLabel label = new JLabel("New label");
			add(label, "2, 8, right, default");
		}
		{
			textField_1 = new JTextField();
			add(textField_1, "4, 8, fill, default");
			textField_1.setColumns(10);
		}
		{
			JLabel label = new JLabel("New label");
			add(label, "2, 10, right, default");
		}
		{
			textField_2 = new JTextField();
			add(textField_2, "4, 10, fill, default");
			textField_2.setColumns(10);
		}
		{
			JButton button = new JButton("New button");
			add(button, "4, 12, right, default");
		}

	}

	public void choose_idp() {
		// TODO Auto-generated method stub
		try {
			Thread.sleep(50000);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public String get_idp() {
		// TODO Auto-generated method stub
		return null;
	}

	public void set_idps(Map idps) {

		
		for (Object idp : idps.keySet()) {
			idpModel.addElement(idp);
		}
	}

}
