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
package eu.europa.ec.markt.dss.applet.component.model;

import eu.europa.ec.markt.dss.DSSUtils;
import org.w3c.dom.*;

import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;
import java.util.Vector;

/**
 * TODO
 *
 *
 *
 *
 *
 *
 */
public class XMLTreeModel implements TreeModel {


    public static class XMLTreeNode {
        private final Node element;

        public XMLTreeNode(Node element) {
            this.element = element;
        }

        public Node getElement() {
            return element;
        }

        public String toString() {
            final String text = getText();
            final String nodeName = element.getNodeName();
            if (DSSUtils.isNotBlank(text)) {
                return nodeName + ": " + text;
            } else {
                return nodeName;
            }
        }

        public String getText() {
            NodeList list = element.getChildNodes();
            for (int i = 0; i < list.getLength(); i++) {
                if (list.item(i) instanceof Text) {
                    return ((Text) list.item(i)).getTextContent();
                }
            }
            return "";
        }
    }

    private Element document;

    private Vector<TreeModelListener> listeners = new Vector<TreeModelListener>();

    public Element getDocument() {
        return document;
    }

    public void setDocument(Element document) {
        this.document = document;
        final TreeModelEvent evt = new TreeModelEvent(this, new TreePath(getRoot()));
        for (TreeModelListener listener : listeners) {
            listener.treeStructureChanged(evt);
        }
    }

    public void addTreeModelListener(TreeModelListener listener) {
        if (!listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    public void removeTreeModelListener(TreeModelListener listener) {
        listeners.remove(listener);
    }

    public Object getChild(Object parent, int index) {
        if (parent instanceof XMLTreeNode) {
            final Vector<Node> elements = getChildElements(((XMLTreeNode) parent).getElement());
            return new XMLTreeNode(elements.get(index));
        } else {
            return null;
        }
    }

    public int getChildCount(Object parent) {
        if (parent instanceof XMLTreeNode) {
            final Vector<Node> elements = getChildElements(((XMLTreeNode) parent).getElement());
            return elements.size();
        }
        return 0;
    }

    public int getIndexOfChild(Object parent, Object child) {
        if (parent instanceof XMLTreeNode && child instanceof XMLTreeNode) {
            final Node pElement = ((XMLTreeNode) parent).getElement();
            final Node cElement = ((XMLTreeNode) child).getElement();
            if (cElement.getParentNode() != pElement) {
                return -1;
            }
            final Vector<Node> elements = getChildElements(pElement);
            return elements.indexOf(cElement);
        }
        return -1;
    }

    public Object getRoot() {
        if (document == null) {
            return null;
        }
        return new XMLTreeNode(document);
    }

    public boolean isLeaf(Object node) {
        if (node instanceof XMLTreeNode) {
            final Node element = ((XMLTreeNode) node).getElement();
            final Vector<Node> elements = getChildElements(element);
            return elements.size() == 0;
        } else {
            return true;
        }
    }


    public void valueForPathChanged(TreePath path, Object newValue) {
        throw new UnsupportedOperationException();
    }

    private Vector<Node> getChildElements(final Node node) {
        final Vector<Node> elements = new Vector<Node>();

        final NamedNodeMap attributes = node.getAttributes();
        if (attributes != null) {
            for (int i = 0; i < attributes.getLength(); i++) {
                elements.add(attributes.item(i));
            }
        }

        final NodeList list = node.getChildNodes();
        for (int i = 0; i < list.getLength(); i++) {
            if (list.item(i).getNodeType() == Node.ELEMENT_NODE) {
                elements.add(list.item(i));
            }
        }
        return elements;
    }
}
