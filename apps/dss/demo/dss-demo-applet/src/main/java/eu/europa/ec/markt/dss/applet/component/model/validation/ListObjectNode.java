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

import javax.xml.bind.annotation.XmlElement;
import java.lang.reflect.Field;
import java.util.List;

/**
 *
 * TODO
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class ListObjectNode extends AbstractListNode {

    /**
     * @see AbstractListNode constructor
     */
    public ListObjectNode(final TreeNode parent, final Object bean, final Field field, final Object itemInList) {
        super(parent, bean, field, itemInList);
    }

    @Override
    public String getTitle() {
        return field.getAnnotation(XmlElement.class).name();
    }

    @Override
    public List<TreeNode> getChildren() {
        return getChildren(itemInList);
    }

    @Override
    public String toString() {
        return "ListObjectNode{" +
              "bean=" + bean +
              ", field=" + field +
              ", itemInList=" + itemInList +
              '}';
    }
}
