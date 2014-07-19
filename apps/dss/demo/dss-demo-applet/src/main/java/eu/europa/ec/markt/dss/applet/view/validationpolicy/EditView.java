/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */
package eu.europa.ec.markt.dss.applet.view.validationpolicy;

import com.jgoodies.forms.builder.PanelBuilder;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.FormLayout;
import eu.europa.ec.markt.dss.applet.component.model.XmlDomAdapterNode;
import eu.europa.ec.markt.dss.applet.component.model.validation.*;
import eu.europa.ec.markt.dss.applet.model.ValidationPolicyModel;
import eu.europa.ec.markt.dss.applet.util.ComponentFactory;
import eu.europa.ec.markt.dss.applet.util.ResourceUtils;
import eu.europa.ec.markt.dss.applet.wizard.validationpolicy.ValidationPolicyWizardController;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.AppletCore;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardView;
import eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.constraint.XsdNode;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;

import org.w3c.dom.*;

import javax.swing.*;
import javax.swing.event.TreeModelEvent;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeCellRenderer;
import javax.swing.tree.TreePath;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.lang.reflect.Field;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class EditView extends WizardView<ValidationPolicyModel, ValidationPolicyWizardController> {

	private JTree validationPolicyTree;
	private JScrollPane scrollPane;
	private ValidationPolicyTreeModel validationPolicyTreeModel;
	final TreeCellRenderer treeCellRenderer = new XMLTreeCellRenderer();

	/**
	 * The default constructor for EditView.
	 *
	 * @param core
	 * @param controller
	 * @param model
	 */
	public EditView(AppletCore core, ValidationPolicyWizardController controller, ValidationPolicyModel model) {
		super(core, controller, model);

		validationPolicyTree = ComponentFactory.tree("tree", null, treeCellRenderer);
		scrollPane = ComponentFactory.createScrollPane(validationPolicyTree);

	}

	@Override
	public void doInit() {
		validationPolicyTreeModel = new ValidationPolicyTreeModel(getModel().getValidationPolicy());
		validationPolicyTree = ComponentFactory.tree("tree", validationPolicyTreeModel, treeCellRenderer);

		scrollPane = ComponentFactory.createScrollPane(validationPolicyTree);
		registerMouseListener(validationPolicyTree);
	}

	/**
	 * fully expand the tree
	 *
	 * @param tree
	 */
	private void expandTree(JTree tree) {
		// expand all
		for (int i = 0; i < tree.getRowCount(); i++) {
			tree.expandRow(i);
		}
	}

	private void registerMouseListener(final JTree tree) {

		MouseListener mouseAdapter = new MouseAdapter() {
			public void mousePressed(MouseEvent mouseEvent) {
				if (mouseEvent.getButton() == MouseEvent.BUTTON3) {
					final int selectedRow = tree.getRowForLocation(mouseEvent.getX(), mouseEvent.getY());
					final TreePath selectedPath = tree.getPathForLocation(mouseEvent.getX(), mouseEvent.getY());
					if (selectedRow != -1) {
						final XmlDomAdapterNode clickedItem = (XmlDomAdapterNode) selectedPath.getLastPathComponent();
						final boolean isLeaf = tree.getModel().isLeaf(selectedPath.getLastPathComponent());
						// Do nothing on root element
						if (selectedPath.getPathCount() > 1) {
							// find the allowed actions, to know if a popup menu should be displayed and the content of the popup menu + action handlers
							if (clickedItem.node instanceof Element) {
								nodeActionAdd(mouseEvent, selectedRow, selectedPath, clickedItem, tree);
							} else if (isLeaf) {
								valueLeafActionEdit(mouseEvent, selectedPath, clickedItem, tree);
							}
						}
					}
				}
			}
		};
		tree.addMouseListener(mouseAdapter);
	}

	String getXPath(Node node) {
		Node parent = node.getParentNode();
		if (parent == null || parent instanceof Document) {
			return node.getNodeName();
		}
		return getXPath(parent) + "/" + node.getNodeName();
	}

	private ArrayList<XsdNode> getChildren(HashMap<String, Object> xsdTree, String xPathClickedItem) {
		ArrayList<XsdNode> result = new ArrayList<XsdNode>();
		String[] splitPath = xPathClickedItem.split("/");
		//Get children
		HashMap<String, Object> childrenMap = getChild(xPathClickedItem, 0, xsdTree);
		//We found some children
		if (childrenMap != null) {
			for (Map.Entry<String, Object> entry : childrenMap.entrySet()) {
				XsdNode n = null;
				Object value = entry.getValue();
				boolean elementExists = false;
				if (value == null) {
					//Check if this attribute is already present
					elementExists = getModel().getValidationPolicy().getXmlDom().exists(xPathClickedItem + "[@" + entry.getKey() + "]");
					//Child null = attribute
					n = new XsdNode(XsdNode.nodeType.ATTRIBUTE, entry.getKey());
				} else if (value.toString().equals("|") || value.toString().equals("|n") || value.toString().equals("TEXT")) {
					//Non multiple element
					if (!value.toString().equals("|n")) {
						//Check if this element is already present
						elementExists = getModel().getValidationPolicy().getXmlDom().exists(xPathClickedItem + "/" + entry.getKey());
					}
					//Check if this node is the leaf
					if (!splitPath[splitPath.length - 1].equalsIgnoreCase(entry.getKey().toString())) {
						//Text node
						n = new XsdNode(XsdNode.nodeType.TEXT, entry.getKey());
					} else {
						elementExists = true;
					}
				} else {
					if (value instanceof HashMap) {
						HashMap hashMap = (HashMap) value;
						//if(hashMap.size()==2){
						if (hashMap.get(entry.getKey()) == null || (hashMap.get(entry.getKey()) != null && !hashMap.get(entry.getKey()).toString().equalsIgnoreCase("NTEXT"))) {
							elementExists = getModel().getValidationPolicy().getXmlDom().exists(xPathClickedItem + "/" + entry.getKey());
						}
						//}
					}
					if (((HashMap) value).get(entry.getKey()) != null && ((HashMap) value).get(entry.getKey()).equals("TEXT")) {
						//node element
						n = new XsdNode(XsdNode.nodeType.ELEMENT_TEXT, entry.getKey());
					} else {
						n = new XsdNode(XsdNode.nodeType.ELEMENT, entry.getKey());
					}
				}

				if (!elementExists) {
					result.add(n);
				}
			}
		}
		return result;
	}

	private HashMap<String, Object> getChild(String xPath, int iPath, HashMap<String, Object> xsdTree) {
		String[] xsdPathSplit = xPath.split("/");

		if (iPath < xsdPathSplit.length) {

			String name = xsdPathSplit[iPath];
			if (xsdTree.containsKey(name)) {

				final Object element = xsdTree.get(name);
				if (element != null && element instanceof HashMap) {

					//We reach children
					final HashMap<String, Object> stringObjectHashMap = (HashMap<String, Object>) element;
					if (iPath + 1 == xsdPathSplit.length) {
						return stringObjectHashMap;
					} else {
						//continue into the tree
						return getChild(xPath, iPath + 1, stringObjectHashMap);
					}
				}
			}
		}
		return null;
	}

	private void nodeActionAdd(MouseEvent mouseEvent, final int selectedRow, final TreePath selectedPath, final XmlDomAdapterNode clickedItem, final JTree tree) {
		// popup menu for list -> add
		final JPopupMenu popup = new JPopupMenu();
		//delete node
		final JMenuItem menuItemToDelete = new JMenuItem(ResourceUtils.getI18n("DELETE"));
		menuItemToDelete.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent actionEvent) {
				final Object valueToDelete = clickedItem.node;
				// find the order# of the child to delete
				int treeIndexOfItemToDelete = -1;
				NodeList parentChildrenNode = clickedItem.node.getParentNode().getChildNodes();
				for (int i = 0; i < parentChildrenNode.getLength(); i++) {
					Node child = parentChildrenNode.item(i);
					if (child == valueToDelete) {
						treeIndexOfItemToDelete = i;
						break;
					}
				}

				Node oldChild = parentChildrenNode.item(treeIndexOfItemToDelete);
				oldChild = clickedItem.node.getParentNode().removeChild(oldChild);
				if (treeIndexOfItemToDelete > -1) {
					validationPolicyTreeModel.fireTreeNodesRemoved(selectedPath.getParentPath(), treeIndexOfItemToDelete, oldChild);
				}
			}
		});
		popup.add(menuItemToDelete);

		//Add node/value
		final HashMap<String, Object> xsdTree = getModel().getValidationPolicy().getTreeResult();
		final String xPathClickedItem = getXPath(clickedItem.node);
		final ArrayList<XsdNode> children = getChildren(xsdTree, xPathClickedItem);
		for (final XsdNode childName : children) {
			final String xmlName = childName.getName();
			final String type = (childName.getType().toString());
			final JMenuItem menuItem = new JMenuItem(ResourceUtils.getI18n("ADD") + " (" + xmlName + " " + type.toLowerCase() + ")");
			popup.add(menuItem);
			menuItem.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent actionEvent) {
					int row = selectedRow;
					Document document = getModel().getValidationPolicy().getDocument();
					DocumentBuilderFactory fabrique = null;
					Object newElement = null;
					try {
						fabrique = DocumentBuilderFactory.newInstance();
						fabrique.setNamespaceAware(true);
						DocumentBuilder builder = fabrique.newDocumentBuilder();
						newElement = document.createElementNS("http://dss.markt.ec.europa.eu/validation/diagnostic", xmlName);
						if (childName.getType().equals(XsdNode.nodeType.TEXT)) {
							((Element) newElement).appendChild(document.createTextNode("VALUE"));
						} else if (childName.getType().equals(XsdNode.nodeType.ATTRIBUTE)) {
							newElement = document.createAttribute(xmlName);
						} else if (childName.getType().equals(XsdNode.nodeType.ELEMENT_TEXT)) {
							((Element) newElement).appendChild(document.createTextNode("VALUE"));
						}
						document.normalizeDocument();
					} catch (Exception e) {
						e.printStackTrace();
					}

					int indexOfAddedItem = 0;
					Node newChild = null;
					if (newElement instanceof Element) {
						//Node
						Node item = clickedItem.node.appendChild((Node) newElement);

						final NodeList childrenNode = clickedItem.node.getChildNodes();
						for (int i = 0; i < childrenNode.getLength(); i++) {
							Node n = childrenNode.item(i);
							if (n == item) {
								indexOfAddedItem = i;
								break;
							}
						}

						newChild = childrenNode.item(indexOfAddedItem);
						validationPolicyTreeModel.fireTreeInsert(selectedPath, ((XmlDomAdapterNode) selectedPath.getLastPathComponent()).childCount() - 1, newChild);
						tree.expandPath(selectedPath);
					} else {
						//Attribute
						//validationPolicyTreeModel.fireTreeNodesRemoved();
						Node newNode = clickedItem.node;
						((Attr) newElement).setValue("VALUE");
						((Element) newNode).setAttributeNode(((Attr) newElement));

						final NodeList childrenNode = clickedItem.node.getParentNode().getChildNodes();
						for (int i = 0; i < childrenNode.getLength(); i++) {
							Node n = childrenNode.item(i);
							if (n == clickedItem.node) {
								indexOfAddedItem = i;
								break;
							}
						}
						newChild = childrenNode.item(indexOfAddedItem);
						TreeModelEvent event = new TreeModelEvent(validationPolicyTreeModel, selectedPath.getParentPath(), new int[]{indexOfAddedItem}, new Object[]{newChild});
						validationPolicyTreeModel.fireTreeNodesChanged(event);
						tree.collapsePath(selectedPath.getParentPath());
						tree.expandPath(selectedPath);
					}
					//Update model
					getModel().getValidationPolicy().setXmlDom(new XmlDom(document));
				}
			});

		}
		popup.show(tree, mouseEvent.getX(), mouseEvent.getY());
	}

	private void abstractListNodeActionDelete(MouseEvent mouseEvent, final TreePath selectedPath, final AbstractListNode clickedItem, JTree tree) {
		// List item -> delete
		JPopupMenu popup = new JPopupMenu();
		final JMenuItem menuItem = new JMenuItem(ResourceUtils.getI18n("DELETE"));
		menuItem.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent actionEvent) {
				final Object valueToDelete = clickedItem.getItemInList();
				final int indexOfDeleted = clickedItem.delete();
			}
		});
		popup.add(menuItem);
		popup.show(tree, mouseEvent.getX(), mouseEvent.getY());
	}

	private void listValueLeafActionEdit(final MouseEvent mouseEvent, final TreePath selectedPath, final ListValueLeaf clickedItem, final JTree tree) {
		// List item : edit
		final JPopupMenu popup = new JPopupMenu();
		if (clickedItem.isBoolean()) {
			final JMenuItem menuItem = new JMenuItem(ResourceUtils.getI18n("TOGGLE"));
			menuItem.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent actionEvent) {
					final Boolean oldValue = (Boolean) clickedItem.getItemInList();
					try {
						clickedItem.setNewValue(Boolean.toString(!oldValue));
					} catch (ParseException e) {
						throw new RuntimeException(e);
					}
					validationPolicyTreeModel.fireTreeChanged(selectedPath);
				}
			});
			popup.add(menuItem);
			//        } else if (clickedItem.isDate()) {
		} else {
			final JMenuItem menuItem = new JMenuItem(ResourceUtils.getI18n("EDIT"));
			menuItem.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent actionEvent) {
					final String newValue = JOptionPane.showInputDialog(ResourceUtils.getI18n("EDIT"), clickedItem.getTitle());
					if (newValue != null) {
						try {
							clickedItem.setNewValue(newValue);
						} catch (ParseException e) {
							showErrorMessage(newValue, tree);
						} catch (NumberFormatException e) {
							showErrorMessage(newValue, tree);
						}
						validationPolicyTreeModel.fireTreeChanged(selectedPath);
					}
				}
			});
			popup.add(menuItem);
		}

		popup.show(tree, mouseEvent.getX(), mouseEvent.getY());

	}

	private void valueLeafActionEdit(final MouseEvent mouseEvent, final TreePath selectedPath, final XmlDomAdapterNode clickedItem, final JTree tree) {

		final JPopupMenu popup = new JPopupMenu();

		// Basic type : edit
		final JMenuItem menuItem = new JMenuItem(ResourceUtils.getI18n("EDIT"));
		menuItem.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent actionEvent) {
				final String newValue = JOptionPane.showInputDialog(ResourceUtils.getI18n("EDIT"), clickedItem.node.getNodeValue());
				if (newValue != null) {
					try {
						if (clickedItem.node instanceof Attr) {
							((Attr) clickedItem.node).setValue(newValue);
						} else {
							clickedItem.node.setNodeValue(newValue);
						}
						//clickedItem.setNewValue(newValue);
					} catch (NumberFormatException e) {
						showErrorMessage(newValue, tree);
					}
					validationPolicyTreeModel.fireTreeChanged(selectedPath);
				}
			}
		});
		popup.add(menuItem);

		popup.show(tree, mouseEvent.getX(), mouseEvent.getY());

	}

	private void showErrorMessage(String newValue, JTree tree) {
		JOptionPane.showMessageDialog(tree, ResourceUtils.getI18n("INVALID_VALUE") + " (" + newValue + ")");
	}

	@Override
	protected Container doLayout() {
		final FormLayout layout = new FormLayout("5dlu, fill:default:grow, 5dlu", "5dlu, fill:default:grow, 5dlu");
		final PanelBuilder builder = ComponentFactory.createBuilder(layout);
		final CellConstraints cc = new CellConstraints();

		builder.add(scrollPane, cc.xy(2, 2));

		return ComponentFactory.createPanel(builder);
	}
}
