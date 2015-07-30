/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.applet.util;

import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.FlowLayout;
import java.awt.LayoutManager;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.ButtonModel;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JApplet;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.UIManager;
import javax.swing.border.Border;

import org.apache.commons.lang.StringUtils;

import com.jgoodies.binding.adapter.BasicComponentFactory;
import com.jgoodies.binding.adapter.RadioButtonAdapter;
import com.jgoodies.binding.value.ValueModel;
import com.jgoodies.forms.builder.PanelBuilder;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.FormLayout;

/**
 * TODO
 */
public final class ComponentFactory extends BasicComponentFactory {

	private static final Color DEFAULT_BACKGROUND = Color.WHITE;
	private static final Color DEFAULT_HIGHLIGHT = new Color(0x99, 0xCC, 0xFF);

	private static final Icon ICON_BACK;
	private static final Icon ICON_NEXT;
	private static final Icon ICON_WAIT;
	private static final Icon ICON_REFRESH;
	private static final Icon ICON_CANCEL;
	private static final Icon ICON_FILE;
	private static final Icon ICON_SUCCESS;

	static {
		ICON_NEXT = new ImageIcon(ResourceUtils.class.getResource("/eu/europa/esig/dss/applet/wizard/arrow_right.png"));
		ICON_BACK = new ImageIcon(ResourceUtils.class.getResource("/eu/europa/esig/dss/applet/wizard/arrow_left.png"));
		ICON_CANCEL = new ImageIcon(ResourceUtils.class.getResource("/eu/europa/esig/dss/applet/wizard/cancel.png"));
		ICON_WAIT = new ImageIcon(ResourceUtils.class.getResource("/eu/europa/esig/dss/applet/wizard/wait.png"));
		ICON_REFRESH = new ImageIcon(ResourceUtils.class.getResource("/eu/europa/esig/dss/applet/wizard/refresh.png"));
		ICON_FILE = UIManager.getIcon("FileView.fileIcon");
		ICON_SUCCESS = new ImageIcon(ResourceUtils.class.getResource("/eu/europa/esig/dss/applet/wizard/big_ok.png"));
	}

	/**
	 * @param components
	 * @return
	 */
	public static JPanel actionPanel(final JComponent... components) {

		final JPanel panel = ComponentFactory.createPanel();
		panel.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Color.GRAY));

		for (final JComponent component : components) {
			panel.add(component);
		}

		return panel;
	}

	/**
	 * @param panel
	 * @param components
	 */
	public static void addToPanel(final JPanel panel, final JComponent... components) {
		for (final JComponent component : components) {
			panel.add(component);
		}
	}

	/**
	 * @param enabled
	 * @param actionListener
	 * @return
	 */
	public static JButton createBackButton(final boolean enabled, final ActionListener actionListener) {
		return ComponentFactory.createButton(ResourceUtils.getI18n("BACK"), enabled, actionListener, ICON_BACK);
	}

	/**
	 * @param layout
	 * @return
	 */
	public static PanelBuilder createBuilder(final FormLayout layout) {
		// return new PanelBuilder(layout, new FormDebugPanel());
		return new PanelBuilder(layout);
	}

	/**
	 * @param layout
	 * @param panel
	 * @return
	 */
	public static PanelBuilder createBuilder(final FormLayout layout, final JPanel panel) {
		return new PanelBuilder(layout, panel);
	}

	public static PanelBuilder createBuilder(final String[] columnSpecs, final String[] rowSpecs) {
		return createBuilder(new FormLayout(StringUtils.join(columnSpecs, ","), StringUtils.join(rowSpecs, ",")));
	}

	/**
	 * @param label
	 * @param actionListener
	 * @param enabled
	 * @return
	 */
	public static JButton createButton(final String label, final boolean enabled, final ActionListener actionListener) {
		final JButton button = new JButton(label);
		button.setEnabled(enabled);
		button.addActionListener(actionListener);
		return button;

	}

	/**
	 * @param label
	 * @param enabled
	 * @param actionListener
	 * @param icon
	 * @return
	 */
	public static JButton createButton(final String label, final boolean enabled, final ActionListener actionListener, final Icon icon) {
		final JButton button = createButton(label, enabled, actionListener);
		button.setIcon(icon);
		return button;
	}

	/**
	 * @param enabled
	 * @param actionListener
	 * @return
	 */
	public static JButton createCancelButton(final boolean enabled, final ActionListener actionListener) {
		return ComponentFactory.createButton(ResourceUtils.getI18n("CANCEL"), enabled, actionListener, ICON_CANCEL);
	}

	/**
	 * @param label
	 * @param enabled
	 * @param actionListener
	 * @return
	 */
	public static JButton createFileChooser(final String label, final boolean enabled, final ActionListener actionListener) {
		return ComponentFactory.createButton(label, enabled, actionListener, ICON_FILE);
	}

	/**
	 * @param text
	 * @return
	 */
	public static JLabel createLabel(final String text) {
		return new JLabel(text);
	}

	/**
	 * @param text
	 * @param icon
	 * @return
	 */
	public static JLabel createLabel(final String text, final Icon icon) {
		final JLabel label = new JLabel(text);
		label.setIcon(icon);
		return label;
	}

	/**
	 * @param enabled
	 * @param actionListener
	 * @return
	 */
	public static JButton createNextButton(final boolean enabled, final ActionListener actionListener) {
		return ComponentFactory.createButton(ResourceUtils.getI18n("NEXT"), enabled, actionListener, ICON_NEXT);
	}

	/**
	 * @return
	 */
	public static JPanel createPanel() {
		return createPanel(DEFAULT_BACKGROUND);
	}

	/**
	 * @param bgColor
	 * @return
	 */
	public static JPanel createPanel(final Color bgColor) {
		return createPanel(new FlowLayout(), bgColor);
	}

	/**
	 * @param components
	 * @return
	 */
	public static JPanel createPanel(final JComponent... components) {
		final JPanel panel = createPanel();
		addToPanel(panel, components);
		return panel;
	}

	/**
	 * @param layout
	 * @return
	 */
	public static JPanel createPanel(final LayoutManager layout) {
		return createPanel(layout, DEFAULT_BACKGROUND);
	}

	/**
	 * @param layout
	 * @param bgColor
	 * @return
	 */
	public static JPanel createPanel(final LayoutManager layout, final Color bgColor) {
		final JPanel panel = new JPanel(layout);
		panel.setOpaque(true);
		panel.setBackground(bgColor);
		return panel;
	}

	/**
	 * @param builder
	 * @return
	 */
	public static JPanel createPanel(final PanelBuilder builder) {
		final JPanel panel = builder.build();
		panel.setOpaque(true);
		panel.setBackground(DEFAULT_BACKGROUND);
		return panel;
	}

	/**
	 * @param text
	 * @param valueModel
	 * @param value
	 * @return
	 */
	public static JRadioButton createRadioButton(final String text, final ValueModel valueModel, final Object value) {
		final JRadioButton button = new JRadioButton(text);
		final ButtonModel model = new RadioButtonAdapter(valueModel, value);
		button.setModel(model);
		return button;
	}

	/**
	 * @param enabled
	 * @param actionListener
	 * @return
	 */
	public static JButton createRefreshButton(final boolean enabled, final ActionListener actionListener) {
		return ComponentFactory.createButton(ResourceUtils.getI18n("REFRESH"), enabled, actionListener, ICON_REFRESH);
	}

	/**
	 * @param component
	 * @return
	 */
	public static JScrollPane createScrollPane(final Component component) {
		final JScrollPane pane = new JScrollPane();
		pane.setViewportView(component);
		return pane;
	}

	/**
	 * @param currentStep
	 * @param maxStep
	 * @return
	 */
	public static JPanel createWizardStepPanel(final int currentStep, final int maxStep) {

		final List<String> colSpecs = new ArrayList<String>();

		for (int i = 1; i <= maxStep; i++) {
			colSpecs.add("default:grow");
		}

		final FormLayout layout = new FormLayout(StringUtils.join(colSpecs, ","), "pref");
		final PanelBuilder builder = ComponentFactory.createBuilder(layout);
		final CellConstraints cc = new CellConstraints();

		for (int i = 1; i <= maxStep; i++) {
			final JPanel subPanel = ComponentFactory.createPanel(i == currentStep ? DEFAULT_HIGHLIGHT : DEFAULT_BACKGROUND);
			subPanel.add(ComponentFactory.createLabel(String.valueOf(i)));

			final Border border = (i != maxStep) ? BorderFactory.createMatteBorder(0, 1, 0, 0, Color.GRAY) : BorderFactory.createMatteBorder(0, 1, 0, 1, Color.GRAY);
			subPanel.setBorder(border);
			builder.add(subPanel, cc.xy(i, 1));
		}

		final JPanel panel = ComponentFactory.createPanel(builder);
		panel.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 0, Color.GRAY));
		return panel;
	}

	/**
	 * @return
	 */
	public static Icon iconSuccess() {
		return ICON_SUCCESS;
	}

	public static Icon iconWait() {
		return ICON_WAIT;
	}

	/**
	 * @param applet
	 * @param container
	 */
	public static void updateDisplay(final JApplet applet, final Container container) {
		if (container != null) {

			final PanelBuilder builder = createBuilder(new String[] {
					"5dlu", "fill:default:grow", "5dlu"
			}, new String[] {
					"5dlu", "fill:default:grow", "5dlu"
			});
			final CellConstraints cc = new CellConstraints();
			builder.add(container, cc.xy(2, 2));

			final JPanel panel = createPanel(builder);
			panel.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 1, Color.GRAY));

			applet.getContentPane().removeAll();
			applet.getContentPane().add(panel);
			applet.getContentPane().validate();
			applet.getContentPane().repaint();

		}
	}

	private ComponentFactory() {
	}

}
