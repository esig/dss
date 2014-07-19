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

import java.lang.reflect.Field;
import java.util.List;

/**
 * Base class representing a List item. One object is created per item in a List.
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public abstract class AbstractListNode extends TreeNode {
    final Object bean;
    final Field field;
    Object itemInList;

    /**
     *
     * @param parent the parent node
     * @param bean the bean containing the List field
     * @param field the field holding the List
     * @param itemInList the item in the list
     */
    AbstractListNode(TreeNode parent, Object bean, Field field, Object itemInList) {
        super(parent);
        this.bean = bean;
        this.field = field;
        this.itemInList = itemInList;
    }


    List getList() {
        return (List) getFieldValue(bean, field);
    }


    public int delete() {
        final List list = getList();
        final int index = list.indexOf(itemInList);
        if (index > -1) {
            list.remove(index);
            return index;
        } else {
            return -1;
        }
    }

    public Object getItemInList() {
        return itemInList;
    }

    public void setItemInList(Object itemInList) {
        this.itemInList = itemInList;
    }
}
