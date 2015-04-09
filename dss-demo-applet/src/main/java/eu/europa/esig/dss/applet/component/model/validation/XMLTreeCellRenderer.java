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
package eu.europa.esig.dss.applet.component.model.validation;

import java.awt.Color;
import java.awt.Component;

import javax.swing.JTree;
import javax.swing.tree.DefaultTreeCellRenderer;

import eu.europa.esig.dss.applet.component.model.XmlDomAdapterNode;

/**
 * Created by kaczmani on 10/04/2014.
 */
public class XMLTreeCellRenderer extends DefaultTreeCellRenderer {

    //colors for tree items
    private final Color elementColor = new Color(0, 0, 128);
    private final Color textColor = new Color(0, 128, 0);

    //remove icons
    public XMLTreeCellRenderer() {
    }

    @Override
    public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded, boolean leaf, int row, boolean hasFocus) {
        XmlDomAdapterNode adapterNode = (XmlDomAdapterNode)value;
        if(!leaf) {
            value = adapterNode.node.getNodeName();
        } else {
            if(adapterNode.node != null && adapterNode.node.getFirstChild() != null) {
                value = adapterNode.node.getFirstChild().getNodeValue();
            }else if(adapterNode.node != null){
                if(adapterNode.node.getNodeValue() != null) {
                    value = adapterNode.node.getNodeValue();
                }else{
                    leaf = false;
                    value = adapterNode.node.getNodeName();
                }
            }
        }

        super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);

        return this;
    }
}
