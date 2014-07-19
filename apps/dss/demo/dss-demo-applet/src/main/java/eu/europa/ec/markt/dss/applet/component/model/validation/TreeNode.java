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
import java.util.*;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlValue;

import eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.constraint.ValidationPolicy;

/**
 * Parent class of each node
 *
 * TODO
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public abstract class TreeNode {

    private static final boolean DISPLAY_EMPTY_ELEMENTS = false;

    private final TreeNode parent;

    protected TreeNode(TreeNode parent) {
        this.parent = parent;
    }

    public abstract String getTitle();

    public abstract List<TreeNode> getChildren();

    List<TreeNode> getChildren(Object bean) {

        List<TreeNode> result = new ArrayList<TreeNode>();
        if (bean == null) {
            return result;
        }

        final List<Field> declaredFields = getDeclaredField(bean.getClass());

        for (Field declaredField : declaredFields) {
            parseXmlAttributeAnnotation(bean, result, declaredField);
            parseXmlElementAnnotation(bean, result, declaredField);
            parseXmlValueAnnotation(bean, result, declaredField);
        }
        return result;
    }

    void parseXmlElementAnnotation(Object source, List<TreeNode> result, Field declaredField) {
        XmlElement xmlElementAnnotation = declaredField.getAnnotation(XmlElement.class);
        if (xmlElementAnnotation != null && isDisplayed(declaredField)) {
            List<TreeNode> value = getTreeNodes(source, declaredField);
            for (final TreeNode treeNode : value) {
                if (DISPLAY_EMPTY_ELEMENTS || treeNode.getFieldValue(source, declaredField) != null) {
                    result.addAll(value);
                    break;
                }
            }
        }
    }

    void parseXmlAttributeAnnotation(Object source, List<TreeNode> result, Field declaredField) {
        XmlAttribute xmlAttributeAnnotation = declaredField.getAnnotation(XmlAttribute.class);
        if (xmlAttributeAnnotation != null && isDisplayed(declaredField)) {
            result.add(new ValueNode(this, source, declaredField));
        }
    }

    void parseXmlValueAnnotation(Object source, List<TreeNode> result, Field declaredField) {
        XmlValue xmlValueAnnotation = declaredField.getAnnotation(XmlValue.class);
        if (xmlValueAnnotation != null && isDisplayed(declaredField)) {
            ValueLeaf valueLeaf = new ValueLeaf(this, source, declaredField);
            if (DISPLAY_EMPTY_ELEMENTS || valueLeaf.getValue() != null) {
                result.add(valueLeaf);
            }
        }
    }

    private List<TreeNode> getTreeNodes(Object source, Field declaredField) {
        List<TreeNode> result = new ArrayList<TreeNode>();
        final Class<?> type = declaredField.getType();
        if (type.equals(Integer.class) || type.equals(int.class) || type.equals(Boolean.class) || type.equals(boolean.class) || type.equals(Date.class) || type
              .equals(String.class)) {
            result.add(new ValueNode(this, source, declaredField));
        } else if (type.equals(List.class)) {
            final List list = (List) getFieldValue(source, declaredField);
            for (Object item : list) {
                final Class<?> itemClass = item.getClass();
                if (itemClass.equals(Boolean.class) || itemClass.equals(Integer.class) || itemClass.equals(Date.class) || itemClass.equals(String.class)) {
                    result.add(new ListValueNode(this, source, declaredField, item));
                } else {
                    result.add(new ListObjectNode(this, source, declaredField, item));
                }
            }
        } else {
            result.add(new BeanNode(this, getFieldValue(source, declaredField), declaredField));
        }

        return result;
    }

    private boolean isDisplayed(Field declaredField) {
        return true;
    }

    public ValidationPolicy getValidationPolicy() {
        TreeNode node = this;
        while (node.getParent() != null) {
            node = node.getParent();
        }
        ValidationPolicyTreeRoot validationPolicyTreeRoot = (ValidationPolicyTreeRoot) node;
        return validationPolicyTreeRoot.getValidationPolicy();
    }

    public String getDateFormat() {

        /*final Cryptographic cryptographic = getValidationPolicy().getCryptographic();
        if (cryptographic != null) {

            final AlgoExpirationDateList algoExpirationDateList = cryptographic.getAlgoExpirationDateList();
            if (algoExpirationDateList != null) {

                final String format = algoExpirationDateList.getFormat();
                if (format != null && !format.isEmpty()) {

                    return format;
                }
            }
        }*/
        return "yyyy-MM-dd";
    }

    public TreeNode getParent() {
        return parent;
    }

    Object getFieldValue(Object source, Field declaredField) {
        declaredField.setAccessible(true);
        try {
            return declaredField.get(source);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } finally {
            declaredField.setAccessible(false);
        }
    }

    /**
     * @param clazz
     * @return all declared field from this clazz and its superclasses
     */
    List<Field> getDeclaredField(Class clazz) {
        if (Object.class.equals(clazz)) {
            return new ArrayList<Field>();
        } else {
            final List<Field> fields = getDeclaredField(clazz.getSuperclass());
            fields.addAll(Arrays.asList(clazz.getDeclaredFields()));
            return fields;
        }
    }
}
