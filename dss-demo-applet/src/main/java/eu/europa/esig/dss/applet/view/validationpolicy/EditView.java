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
package eu.europa.esig.dss.applet.view.validationpolicy;

import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.event.TreeModelEvent;
import javax.swing.tree.TreeCellRenderer;
import javax.swing.tree.TreePath;

import org.apache.commons.lang.StringUtils;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.jgoodies.forms.builder.PanelBuilder;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.FormLayout;

import eu.europa.esig.dss.XmlDom;
import eu.europa.esig.dss.applet.component.model.XmlDomAdapterNode;
import eu.europa.esig.dss.applet.component.model.XsdNode;
import eu.europa.esig.dss.applet.component.model.XsdNodeCardinality;
import eu.europa.esig.dss.applet.component.model.XsdNodeType;
import eu.europa.esig.dss.applet.component.model.validation.ValidationPolicyTreeModel;
import eu.europa.esig.dss.applet.component.model.validation.XMLTreeCellRenderer;
import eu.europa.esig.dss.applet.model.ValidationPolicyModel;
import eu.europa.esig.dss.applet.swing.mvc.AppletCore;
import eu.europa.esig.dss.applet.swing.mvc.wizard.WizardView;
import eu.europa.esig.dss.applet.util.ComponentFactory;
import eu.europa.esig.dss.applet.util.ResourceUtils;
import eu.europa.esig.dss.applet.wizard.validationpolicy.ValidationPolicyWizardController;

/**
 * TODO
 *
 *
 *
 *
 *
 *
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
			@Override
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
		if ((parent == null) || (parent instanceof Document)) {
			return node.getNodeName();
		}
		return getXPath(parent) + "/" + node.getNodeName();
	}

	/**
	 * @param element
	 * @param xsdTree
	 * @return The list of XsdNode that are possible to add as childs to this node
	 */
	private List<XsdNode> getChildrenToAdd(Element element, Map<XsdNode, Object> xsdTree) {
		String xPathClickedItem = getXPath(element);
		List<XsdNode> result = new ArrayList<XsdNode>();
		//Get children
		Map<XsdNode, Object> childrenMap = getChild(xPathClickedItem, xsdTree);
		//We found some children
		if (childrenMap != null) {
			for (Map.Entry<XsdNode, Object> entry : childrenMap.entrySet()) {
				final XsdNode xsdNode = entry.getKey();
				final String xmlName = xsdNode.getLastNameOfPath();

				XsdNode xsdNodeAddable = null;
				final boolean elementExists;
				if (xsdNode.getType() == XsdNodeType.ATTRIBUTE) {
					//Check if this attribute is already present
					final String attribute = element.getAttribute(xmlName);
					if (StringUtils.isEmpty(attribute)) {
						elementExists = false;
						xsdNodeAddable = xsdNode;
					} else {
						elementExists = true;
					}
				} else if (xsdNode.getType() == XsdNodeType.ELEMENT) {
					if ((xsdNode.getCardinality() == XsdNodeCardinality.ONCE_EXACTLY) || (xsdNode.getCardinality() == XsdNodeCardinality.ONCE_OPTIONALY)) {
						// check if this item already exist as a child of this item. If not, it can be added.
						elementExists = getModel().getValidationPolicy().getXmlDom().exists(xsdNode.getName());
						if (!elementExists) {
							xsdNodeAddable = xsdNode;
						}
					} else {
						// multiple element, we can add more of it
						elementExists = false;
						xsdNodeAddable = xsdNode;

					}
				} else if (xsdNode.getType() == XsdNodeType.TEXT) {
					final XmlDom xmlDomElement = new XmlDom(element);
					if ((element != null) && (xmlDomElement.getText() != null) && (xmlDomElement.getText().length() > 0)) {
						elementExists = true;
					} else {
						elementExists = false;
						xsdNodeAddable = xsdNode;
					}
				} else {
					throw new IllegalArgumentException("Unknown type " + xsdNode.getType());
				}

				if (!elementExists && (xsdNodeAddable != null)) {
					result.add(xsdNodeAddable);
				}
			}
		}
		return result;
	}

	private Map<XsdNode, Object> getChild(String xPath, Map<XsdNode, Object> xsdTree) {
		final Set<Map.Entry<XsdNode, Object>> entries = xsdTree.entrySet();
		for (final Map.Entry<XsdNode, Object> entry : entries) {
			if (xPath.startsWith(entry.getKey().getName())) {
				if (xPath.equals(entry.getKey().getName())) {
					return (Map<XsdNode, Object>) entry.getValue();
				} else {
					return getChild(xPath, (Map<XsdNode, Object>) entry.getValue());
				}
			}
		}
		return null;
	}

	private void nodeActionAdd(MouseEvent mouseEvent, final int selectedRow, final TreePath selectedPath, final XmlDomAdapterNode clickedItem, final JTree tree) {
		final Element clickedElement = (Element) clickedItem.node;
		// popup menu for list -> add
		final JPopupMenu popup = new JPopupMenu();
		//delete node
		final JMenuItem menuItemToDelete = new JMenuItem(ResourceUtils.getI18n("DELETE"));
		menuItemToDelete.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent actionEvent) {
				// find the order# of the child to delete
				final int index = clickedItem.getParent().index(clickedItem);

				Node oldChild = clickedElement.getParentNode().removeChild(clickedElement);
				if (index > -1) {
					validationPolicyTreeModel.fireTreeNodesRemoved(selectedPath.getParentPath(), index, oldChild);
				}
			}
		});
		popup.add(menuItemToDelete);

		//Add node/value
		final Map<XsdNode, Object> xsdTree = validationPolicyTreeModel.getXsdTree();
		final List<XsdNode> children = getChildrenToAdd(clickedElement, xsdTree);
		for (final XsdNode xsdChild : children) {
			final String xmlName = xsdChild.getLastNameOfPath();

			final JMenuItem menuItem = new JMenuItem(ResourceUtils.getI18n("ADD") + " (" + xmlName + " " + xsdChild.getType().toString().toLowerCase() + ")");
			popup.add(menuItem);
			menuItem.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent actionEvent) {
					Document document = getModel().getValidationPolicy().getDocument();

					final Node newElement;
					if (xsdChild.getType() == XsdNodeType.TEXT) {
						// TEXT element always appended (last child)
						newElement = clickedElement.appendChild(document.createTextNode("VALUE"));
					} else if (xsdChild.getType() == XsdNodeType.ATTRIBUTE) {
						newElement = document.createAttributeNS(null, xmlName);
						((Attr) newElement).setValue("VALUE");
						clickedElement.setAttributeNode((Attr) newElement);
					} else if (xsdChild.getType() == XsdNodeType.ELEMENT) {
						final Element childToAdd = document.createElementNS("http://dss.esig.europa.eu/validation/diagnostic", xmlName);
						// find the correct possition to add the child
						// Get all allowed children
						Map<XsdNode, Object> childrenMap = getChild(getXPath(clickedElement), xsdTree);
						boolean toAddSeen = false;
						Element elementIsToAddBeforeThisOne = null;
						for (final XsdNode allowed : childrenMap.keySet()) {
							if (!toAddSeen && (allowed == xsdChild)) {
								toAddSeen = true;
								continue;
							}
							if (toAddSeen) {
								final NodeList elementsByTagNameNS = clickedElement
										.getElementsByTagNameNS("http://dss.esig.europa.eu/validation/diagnostic", allowed.getLastNameOfPath());
								if (elementsByTagNameNS.getLength() > 0) {
									// we found an element that is supposed to be after the one to add
									elementIsToAddBeforeThisOne = (Element) elementsByTagNameNS.item(0);
									break;
								}
							}
						}

						if (elementIsToAddBeforeThisOne != null) {
							newElement = clickedElement.insertBefore(childToAdd, elementIsToAddBeforeThisOne);
						} else {
							newElement = clickedElement.appendChild(childToAdd);
						}
					} else {
						throw new IllegalArgumentException("Unknow XsdNode NodeType " + xsdChild.getType());
					}

					document.normalizeDocument();

					int indexOfAddedItem = 0;
					final int childCount = clickedItem.childCount();
					for (int i = 0; i < childCount; i++) {
						if (clickedItem.child(i).node == newElement) {
							indexOfAddedItem = i;
							break;
						}
					}

					TreeModelEvent event = new TreeModelEvent(validationPolicyTreeModel, selectedPath, new int[]{indexOfAddedItem}, new Object[]{newElement});
					validationPolicyTreeModel.fireTreeNodesInserted(event);
					tree.expandPath(selectedPath);

					//Update model
					getModel().getValidationPolicy().setXmlDom(new XmlDom(document));
				}
			});

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
