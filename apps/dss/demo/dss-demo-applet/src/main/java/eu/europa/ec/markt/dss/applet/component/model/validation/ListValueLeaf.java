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
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * This node (leaf) will display the value of a list item.
 * It will display a simple type such as Date, Integer or String.
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class ListValueLeaf extends TreeNode {


    public ListValueLeaf(final ListValueNode parent) {
        super(parent);
    }

    @Override
    public ListValueNode getParent() {
        return (ListValueNode) super.getParent();
    }

    @Override
    public String getTitle() {
        if (getItemInList() instanceof Date) {
            SimpleDateFormat sdf = new SimpleDateFormat(getDateFormat());
            return sdf.format((Date) getItemInList());
        } else {
            return getItemInList().toString();
        }
    }

    @Override
    public List<TreeNode> getChildren() {
        return new ArrayList<TreeNode>();
    }

    public void setNewValue(String newValue) throws ParseException {
        final List list = getList();
        final int index = list.indexOf(getItemInList());
        list.remove(index);


        final Class<?> fieldType = getItemInList().getClass();
        SimpleDateFormat sdf = new SimpleDateFormat(getDateFormat());
        if (Date.class.equals(fieldType)) {
            list.add(index, sdf.parse(newValue));
        } else if (Integer.class.equals(fieldType) || int.class.equals(fieldType)) {
            list.add(index, Integer.parseInt(newValue));
        } else if (Boolean.class.equals(fieldType) || boolean.class.equals(fieldType)) {
            list.add(index, Boolean.parseBoolean(newValue));
        } else {
            list.add(index, newValue);
        }
        getParent().setItemInList(newValue);
    }


    public Object getItemInList() {
        return getParent().getItemInList();
    }

    private List getList() {
        return (List) getFieldValue(getBean(), getField());
    }

    private Field getField() {
        return getParent().getField();
    }

    private Object getBean() {
        return getParent().getBean();
    }

    public boolean isBoolean() {
        return getItemInList().getClass().equals(Boolean.class);
    }

    public boolean isDate() {
        return getItemInList().getClass().equals(Date.class);
    }

    public boolean isInt() {
        return getItemInList().getClass().equals(Integer.class);
    }

}
