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
package eu.europa.esig.dss.applet.component.model;

import java.util.ArrayList;
import java.util.List;

import javax.swing.event.TreeModelListener;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;

/**
 * This abstract class contains common aspects of TreeModel (listeners + abstract getChildren()).
 * 
 * 
 *
 * @param <R>
 */
public abstract class AbstractTreeModel<R> implements TreeModel {

    protected List<TreeModelListener> listeners = new ArrayList<TreeModelListener>();

    private R root;

    /**
     * The default constructor for AbstractTreeModel.
     * 
     * @param root
     */
    public AbstractTreeModel(final R root) {
        this.root = root;
    }

    @Override
    public void addTreeModelListener(final TreeModelListener l) {
        listeners.add(l);
    }

    protected boolean filterThisNode(final Object child) {
        return child == null;
    }

    @Override
    public Object getChild(final Object parent, final int index) {
        return getNonNullChildren(parent).get(index);
    }

    @Override
    public int getChildCount(final Object parent) {
        return getNonNullChildren(parent).size();
    }

    /**
     * Give the list of children of a parent node
     * 
     * @param parent
     * @return
     */
    public abstract List<?> getChildren(Object parent);

    @Override
    public int getIndexOfChild(final Object parent, final Object child) {
        return getNonNullChildren(parent).indexOf(child);
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    List<?> getNonNullChildren(final Object parent) {
        final List list = getChildren(parent);
        final List filtered = new ArrayList();
        for (final Object o : list) {
            if (!filterThisNode(o)) {
                filtered.add(o);
            }
        }
        return filtered;
    }

    @Override
    public R getRoot() {
        return root;
    }

    @Override
    public boolean isLeaf(final Object node) {
        return getChildCount(node) == 0;
    }

    @Override
    public void removeTreeModelListener(final TreeModelListener l) {
        listeners.remove(l);
    }

    @Override
    public void valueForPathChanged(final TreePath path, final Object newValue) {
    }

}
