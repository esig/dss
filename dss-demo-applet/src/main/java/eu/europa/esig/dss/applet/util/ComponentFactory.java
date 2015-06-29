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
import javax.swing.ComboBoxModel;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JApplet;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.ListCellRenderer;
import javax.swing.ListModel;
import javax.swing.UIManager;
import javax.swing.border.Border;
import javax.swing.tree.TreeCellRenderer;
import javax.swing.tree.TreeModel;

import org.apache.commons.lang.StringUtils;

import com.jgoodies.binding.adapter.BasicComponentFactory;
import com.jgoodies.binding.adapter.RadioButtonAdapter;
import com.jgoodies.binding.value.ValueModel;
import com.jgoodies.forms.builder.PanelBuilder;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.FormLayout;

/**
 * TODO
 *
 *
 *
 *
 *
 *
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
	private static final Icon ICON_SAVE_FILE;

	private static final Icon ICON_VALID;
	private static final Icon ICON_INVALID;
	private static final Icon ICON_WARNING;
	private static final Icon ICON_UNSURE;
	private static final Icon ICON_INFO;

	private static final Icon ICON_SUCCESS;

	static {

		// this.getClass().getResource("/eu/europa/esig/dss/applet/wizard/" + name);

		ICON_NEXT = new ImageIcon(ResourceUtils.class.getResource("/eu/europa/esig/dss/applet/wizard/arrow_right.png"));
		ICON_BACK = new ImageIcon(ResourceUtils.class.getResource("/eu/europa/esig/dss/applet/wizard/arrow_left.png"));
		ICON_CANCEL = new ImageIcon(ResourceUtils.class.getResource("/eu/europa/esig/dss/applet/wizard/cancel.png"));
		ICON_WAIT = new ImageIcon(ResourceUtils.class.getResource("/eu/europa/esig/dss/applet/wizard/wait.png"));
		ICON_REFRESH = new ImageIcon(ResourceUtils.class.getResource("/eu/europa/esig/dss/applet/wizard/refresh.png"));
		ICON_FILE = UIManager.getIcon("FileView.fileIcon");
		ICON_SAVE_FILE = UIManager.getIcon("FileChooser.floppyDriveIcon");
		ICON_VALID = new ImageIcon(ResourceUtils.class.getResource("/eu/europa/esig/dss/applet/report/tick_16.png"));
		ICON_INVALID = new ImageIcon(ResourceUtils.class.getResource("/eu/europa/esig/dss/applet/report/block_16.png"));
		ICON_WARNING = new ImageIcon(ResourceUtils.class.getResource("/eu/europa/esig/dss/applet/report/warning_16.png"));
		ICON_UNSURE = new ImageIcon(ResourceUtils.class.getResource("/eu/europa/esig/dss/applet/report/unsure_16.png"));
		ICON_INFO = new ImageIcon(ResourceUtils.class.getResource("/eu/europa/esig/dss/applet/report/info_16.png"));
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
	 * @param text
	 * @param actionListener
	 * @return
	 */
	public static JCheckBox checkButton(final String text, final ActionListener actionListener) {
		final JCheckBox check = new JCheckBox(text);
		check.addActionListener(actionListener);
		return check;
	}

	/**
	 * @param model
	 * @param actionListener
	 * @return
	 */
	public static JComboBox combo(final ComboBoxModel model, final ActionListener actionListener) {
		final JComboBox combo = new JComboBox();
		combo.setModel(model);
		combo.addActionListener(actionListener);
		return combo;
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
	 * @param enabled
	 * @param actionListener
	 * @return
	 */
	public static JButton createClearButton(final boolean enabled, final ActionListener actionListener) {
		return ComponentFactory.createButton(ResourceUtils.getI18n("CLEAR"), enabled, actionListener);
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
		return createPanel(true);
	}

	/**
	 * @param opaque
	 * @return
	 */
	public static JPanel createPanel(final boolean opaque) {
		return createPanel(new FlowLayout(), opaque);
	}

	/**
	 * @param opaque
	 * @param bgColor
	 * @return
	 */
	public static JPanel createPanel(final boolean opaque, final Color bgColor) {
		return createPanel(new FlowLayout(), opaque, bgColor);
	}

	/**
	 * @param bgColor
	 * @return
	 */
	public static JPanel createPanel(final Color bgColor) {
		return createPanel(new FlowLayout(), true, bgColor);
	}

	/**
	 * @param components
	 * @return
	 */
	public static JPanel createPanel(final JComponent... components) {
		final JPanel panel = createPanel(true);
		addToPanel(panel, components);
		return panel;
	}

	/**
	 * @param layout
	 * @return
	 */
	public static JPanel createPanel(final LayoutManager layout) {
		return createPanel(layout, true, DEFAULT_BACKGROUND);
	}

	/**
	 * @param layout
	 * @param opaque
	 * @return
	 */
	public static JPanel createPanel(final LayoutManager layout, final boolean opaque) {
		return createPanel(layout, opaque, DEFAULT_BACKGROUND);
	}

	/**
	 * @param layout
	 * @param bgColor
	 * @param opaque
	 * @return
	 */
	public static JPanel createPanel(final LayoutManager layout, final boolean opaque, final Color bgColor) {
		final JPanel panel = new JPanel(layout);
		panel.setOpaque(opaque);
		panel.setBackground(bgColor);
		return panel;
	}

	/**
	 * @param builder
	 * @return
	 */
	public static JPanel createPanel(final PanelBuilder builder) {
		return createPanel(builder, true);
	}

	/**
	 * @param builder
	 * @param opaque
	 * @return
	 */
	public static JPanel createPanel(final PanelBuilder builder, final boolean opaque) {
		return createPanel(builder, opaque, DEFAULT_BACKGROUND);
	}

	/**
	 * @param builder
	 * @param opaque
	 * @param bgColor
	 * @return
	 */
	public static JPanel createPanel(final PanelBuilder builder, final boolean opaque, final Color bgColor) {
		final JPanel panel = builder.build();
		panel.setOpaque(opaque);
		panel.setBackground(bgColor);
		return panel;
	}

	/**
	 * @param builder
	 * @param bgColor
	 * @return
	 */
	public static JPanel createPanel(final PanelBuilder builder, final Color bgColor) {
		return createPanel(builder, true, bgColor);
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
	 * @param label
	 * @param enabled
	 * @param actionListener
	 * @return
	 */
	public static JButton createSaveButton(final String label, final boolean enabled, final ActionListener actionListener) {
		return ComponentFactory.createButton(label, enabled, actionListener, ICON_SAVE_FILE);
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
	 * @param ressourceName
	 * @return
	 */
	public static ImageIcon icon(final String ressourceName) {
		return new ImageIcon(ComponentFactory.class.getResource(ressourceName));
	}

	/**
	 * @return
	 */
	public static Icon iconInvalid() {
		return ICON_INVALID;
	}

	/**
	 * @return
	 */
	public static Icon iconSuccess() {
		return ICON_SUCCESS;
	}

	/**
	 * @return
	 */
	public static Icon iconUnsure() {
		return ICON_UNSURE;
	}

	/**
	 * @return
	 */
	public static Icon iconValid() {
		return ICON_VALID;
	}

	public static Icon iconWait() {
		return ICON_WAIT;
	}

	/**
	 * @param name
	 * @param model
	 * @param cellRenderer
	 * @return
	 */
	public static JList list(final String name, final ListModel model, final ListCellRenderer cellRenderer) {
		final JList list = new JList();
		list.setName(name);
		list.setModel(model);
		if (cellRenderer != null) {
			list.setCellRenderer(cellRenderer);
		}
		return list;
	}

	/**
	 * @param name
	 * @param model
	 * @return
	 */
	public static JTree tree(final String name, final TreeModel model) {
		return tree(name, model, null);
	}

	/**
	 * @param name
	 * @param model
	 * @param cellRenderer
	 * @return
	 */
	public static JTree tree(final String name, final TreeModel model, final TreeCellRenderer cellRenderer) {
		final JTree tree = new JTree();
		tree.setName(name);
		tree.setModel(model);
		if (cellRenderer != null) {
			tree.setCellRenderer(cellRenderer);
		}
		return tree;
	}

	/**
	 * @param applet
	 * @param container
	 */
	public static void updateDisplay(final JApplet applet, final Container container) {
		if (container != null) {

			final PanelBuilder builder = createBuilder(new String[]{"5dlu", "fill:default:grow", "5dlu"}, new String[]{"5dlu", "fill:default:grow", "5dlu"});
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
