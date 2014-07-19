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
import java.lang.reflect.Modifier;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Represent a value item (XmlAttribute or XmlElement) of a simple type (String, Date, Integer).
 * This node will display the value of the field.
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class ValueLeaf extends TreeNode {

    private final Object bean;

    private final Field field;

    public ValueLeaf(TreeNode parent, Object bean, Field field) {
        super(parent);
        this.bean = bean;
        this.field = field;
    }

    @Override
    public String getTitle() {
        Object value = getValue();
        if (value == null) {
            return "<no value>";
        } else if (value instanceof Date) {
            SimpleDateFormat sdf = new SimpleDateFormat(getDateFormat());
            return sdf.format((Date) value);
        } else {
            return getValue().toString();
        }
    }

    @Override
    public List<TreeNode> getChildren() {
        return new ArrayList<TreeNode>();
    }

    public Object getValue() {
        return getFieldValue(bean, field);
    }

    public void setNewValue(String newValue) throws ParseException {
        field.setAccessible(true);
        try {
            final Class<?> fieldType = field.getType();
            SimpleDateFormat sdf = new SimpleDateFormat(getDateFormat());
            if (Date.class.equals(fieldType)) {
                field.set(bean, sdf.parse(newValue));
            } else if (Integer.class.equals(fieldType) || int.class.equals(fieldType)) {
                field.set(bean, Integer.parseInt(newValue));
            } else if (Boolean.class.equals(fieldType) || boolean.class.equals(fieldType)) {
                field.set(bean, Boolean.parseBoolean(newValue));
            } else {
                field.set(bean, newValue);
            }
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } finally {
            field.setAccessible(false);
        }
    }

    @Override
    public String toString() {
        return "ValueLeaf{" +
              "bean=" + bean +
              ", field=" + field +
              '}';
    }

    public boolean isReadOnly() {
        return Modifier.isFinal(field.getModifiers());
    }

    public boolean isBoolean() {
        final Object value = getValue();
        if (value == null) {
            return false;
        } else {
        return value.getClass().equals(Boolean.class) || value.getClass().equals(boolean.class);
        }
    }

    public boolean isDate() {
        final Object value = getValue();
        if (value == null) {
            return false;
        } else
            return getValue().getClass().equals(Date.class);
    }

    public boolean isInt() {
        final Object value = getValue();
        if (value == null) {
            return false;
        } else {
            return getValue().getClass().equals(Integer.class) || getValue().getClass().equals(int.class);
        }
    }
}
