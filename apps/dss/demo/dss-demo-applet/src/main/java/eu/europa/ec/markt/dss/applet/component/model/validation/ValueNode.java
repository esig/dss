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
package eu.europa.ec.markt.dss.applet.component.model.validation;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

/**
 * Represent a value item (XmlAttribute or XmlElement) of a simple type (String, Date, Integer).
 * This node will not display the value, but the (xml) name of the field.
 *
 * This node will have only one child, a ValueLeaf.
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class ValueNode extends TreeNode {

    private final Object bean;

    private final Field field;

    /**
     *
     * @param parent node
     * @param bean the bean containing the value
     * @param field the bean field to get/set the value
     */
    protected ValueNode(TreeNode parent, Object bean, Field field) {
        super(parent);
        this.bean = bean;
        this.field = field;
    }

    @Override
    public String getTitle() {
        final XmlElement xmlElement = field.getAnnotation(XmlElement.class);
        if (xmlElement != null) {
            return xmlElement.name();
        }

        final XmlAttribute xmlAttribute = field.getAnnotation(XmlAttribute.class);
        if (xmlAttribute != null) {
            return xmlAttribute.name();
        }

        throw new RuntimeException(field.getName() + " : Not a XmlElement nor XmlAttribute");

    }

    @Override
    public List<TreeNode> getChildren() {
        List<TreeNode> result = new ArrayList<TreeNode>();
        final ValueLeaf valueLeaf = new ValueLeaf(this, bean, field);
        result.add(valueLeaf);
        return result;
    }

    @Override
    public String toString() {
        return "ValueNode{" +
              "bean=" + bean +
              ", field=" + field +
              '}';
    }
}
