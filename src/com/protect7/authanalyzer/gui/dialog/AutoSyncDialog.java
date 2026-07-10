package com.protect7.authanalyzer.gui.dialog;

import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ArrayList;
import java.util.Iterator;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;
import javax.swing.border.EmptyBorder;
import com.protect7.authanalyzer.entities.AutoSyncConfig;
import com.protect7.authanalyzer.gui.entity.SessionPanel;
import com.protect7.authanalyzer.gui.util.PlaceholderTextField;

public class AutoSyncDialog extends JDialog {

	private static final long serialVersionUID = 1L;
	private final int TEXTFIELD_WIDTH = 15;
	private final JPanel listPanel = (JPanel) getContentPane();
	private final GridBagConstraints c = new GridBagConstraints();
	private final ArrayList<AutoSyncConfig> autoSyncList;
	private final String INFO_TEXT;
	
	private final PlaceholderTextField triggerNameInput = new PlaceholderTextField(TEXTFIELD_WIDTH);
	private final PlaceholderTextField triggerValueInput = new PlaceholderTextField(TEXTFIELD_WIDTH);
	private final PlaceholderTextField sourceNameInput = new PlaceholderTextField(TEXTFIELD_WIDTH);
	private final PlaceholderTextField regexInput = new PlaceholderTextField(TEXTFIELD_WIDTH);
	private final PlaceholderTextField targetTokenInput = new PlaceholderTextField(TEXTFIELD_WIDTH);
	
	private final JButton addEntryButton = new JButton("\u2795");
	private final JButton okButton = new JButton("OK");
	
	public AutoSyncDialog(SessionPanel sessionPanel) {
		autoSyncList = sessionPanel.getAutoSyncList();
		INFO_TEXT = "Specify Live Proxy Sync rules for the session \""+sessionPanel.getSessionName()+"\"";
		
		triggerNameInput.setPlaceholder("e.g. X-PwnFox-Color");
		triggerValueInput.setPlaceholder("e.g. red");
		sourceNameInput.setPlaceholder("e.g. Cookie");
		regexInput.setPlaceholder("Optional regex");
		targetTokenInput.setPlaceholder("Token name");
		
		listPanel.setLayout(new GridBagLayout());
		listPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

		addEntryButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				addAutoSyncConfig(triggerNameInput.getText(), triggerValueInput.getText(), sourceNameInput.getText(), regexInput.getText(), targetTokenInput.getText());
				updateAutoSyncList();
				SwingUtilities.getWindowAncestor((Component) e.getSource()).pack();
			}
		});
		
		updateAutoSyncList();
		setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);	
		setVisible(true);
		setTitle("Live Proxy Sync for Session " + sessionPanel.getSessionName());
		pack();
		setLocationRelativeTo(sessionPanel);
		
		okButton.addActionListener(e -> {
			addAutoSyncConfig(triggerNameInput.getText(), triggerValueInput.getText(), sourceNameInput.getText(), regexInput.getText(), targetTokenInput.getText());
			dispose();
		});
			
		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosed(WindowEvent e) {
				sessionPanel.updateLiveProxySyncButtonText();
			}
		});
	}

	private void updateAutoSyncList() {
		listPanel.removeAll();
		c.fill = GridBagConstraints.HORIZONTAL;
		c.insets = new Insets(0, 5, 20, 0);
		c.gridx = 0;
		c.gridy = 0;
		c.gridwidth = 6;
		listPanel.add(new JLabel(INFO_TEXT), c);
		
		c.insets = new Insets(0, 5, 5, 0);
		c.gridwidth = 1;
		c.gridy++;
		listPanel.add(new JLabel("Trigger Header:"), c);
		c.gridx = 1;
		listPanel.add(new JLabel("Trigger Value:"), c);
		c.gridx = 2;
		listPanel.add(new JLabel("Source Header:"), c);
		c.gridx = 3;
		listPanel.add(new JLabel("Regex (Optional):"), c);
		c.gridx = 4;
		listPanel.add(new JLabel("Target Token:"), c);
		
		c.gridx = 0;
		c.gridy++;
		listPanel.add(triggerNameInput, c);
		c.gridx = 1;
		listPanel.add(triggerValueInput, c);
		c.gridx = 2;
		listPanel.add(sourceNameInput, c);
		c.gridx = 3;
		listPanel.add(regexInput, c);
		c.gridx = 4;
		listPanel.add(targetTokenInput, c);
		c.gridx = 5;
		listPanel.add(addEntryButton, c);

		c.gridy++;
		for (AutoSyncConfig config : autoSyncList) {
			c.gridx = 0;
			listPanel.add(getFormattedLabel(config.getTriggerHeaderName()), c);
			c.gridx = 1;
			listPanel.add(getFormattedLabel(config.getTriggerHeaderValue()), c);
			c.gridx = 2;
			listPanel.add(getFormattedLabel(config.getSourceHeaderName()), c);
			c.gridx = 3;
			listPanel.add(getFormattedLabel(config.getExtractionRegex()), c);
			c.gridx = 4;
			listPanel.add(getFormattedLabel(config.getTargetTokenName()), c);
			
			JButton deleteEntryBtn = new JButton();
			deleteEntryBtn.setIcon(new ImageIcon(this.getClass().getClassLoader().getResource("delete.png")));
			deleteEntryBtn.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					removeGivenConfig(config);
					updateAutoSyncList();
					SwingUtilities.getWindowAncestor((Component) e.getSource()).pack();
				}
			});
			c.gridx = 5;
			listPanel.add(deleteEntryBtn, c);
			c.gridy++;
		}
		c.insets = new Insets(10, 5, 10, 0);
		listPanel.add(okButton, c);
		listPanel.revalidate();
		listPanel.repaint();
		pack();
	}
	
	private JLabel getFormattedLabel(String text) {
		if (text == null || text.isEmpty()) {
			return new JLabel("-");
		}
		String formattedText;
		if(text.length() > 20) {
			formattedText = text.substring(0, 17) + "...";
		}
		else {
			formattedText = text;
		}
		JLabel label = new JLabel(formattedText);
		label.setToolTipText(text);
		return label;
	}
	
	private void addAutoSyncConfig(String triggerName, String triggerValue, String sourceName, String regex, String targetToken) {
		if (!triggerName.trim().isEmpty() && !sourceName.trim().isEmpty() && !targetToken.trim().isEmpty()) {
			AutoSyncConfig newConfig = new AutoSyncConfig(triggerName.trim(), triggerValue.trim(), sourceName.trim(), regex.trim(), targetToken.trim());
			autoSyncList.add(newConfig);
			triggerNameInput.setText("");
			triggerValueInput.setText("");
			sourceNameInput.setText("");
			regexInput.setText("");
			targetTokenInput.setText("");
		}
	}
	
	private void removeGivenConfig(AutoSyncConfig config) {
		autoSyncList.remove(config);
	}
}
