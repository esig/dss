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
import java.lang.reflect.ParameterizedType;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Itermediate node representing a bean
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class BeanNode extends TreeNode {
    private final Field field;
    private final Object bean;

    /**
     *
     * @param parent the parent node
     * @param bean the bean represented by this node
     * @param declaredField the field containing the bean
     */
    public BeanNode(final TreeNode parent, final Object bean, final Field declaredField) {
        super(parent);
        this.bean = bean;
        this.field = declaredField;
    }

    @Override
    public String getTitle() {
        return field.getAnnotation(XmlElement.class).name();
    }

    @Override
    public List<TreeNode> getChildren() {
        return getChildren(bean);
    }

    public Map<Field, Class> getListFieldsInBean(){
        final Class<?> clazz = bean.getClass();
        final List<Field> declaredFields = getDeclaredField(clazz);
        final Map<Field, Class> result = new HashMap<Field, Class>();
        for (Field field : declaredFields) {
            final XmlElement xmlElementAnnotation = field.getAnnotation(XmlElement.class);
            if (xmlElementAnnotation != null){
                if (field.getType().equals(List.class)){
                    final ParameterizedType listType = (ParameterizedType) field.getGenericType();
                    final Class type = (Class) listType.getActualTypeArguments()[0];
                    result.put(field, type);
                }
            }
        }
        return result;
    }

    @Override
    public String toString() {
        return "BeanNode{" +
              "bean=" + bean +
              ", field=" + field +
              '}';
    }

    public int addListItem(Field listField, Class itemClass) {
        List list = (List) getFieldValue(bean, listField);
        try {
            list.add(itemClass.newInstance());
            return list.size() - 1;
        } catch (InstantiationException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }


    public Object getListItem(Field listField, int indexOfAddedItem) {
        List list = (List) getFieldValue(bean, listField);
        return list.get(indexOfAddedItem);
    }
}
