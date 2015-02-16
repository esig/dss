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

package eu.europa.ec.markt.dss.applet.component.model;

import javax.swing.event.TreeModelListener;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;
import java.util.ArrayList;
import java.util.List;

/**
 * This abstract class contains common aspects of TreeModel (listeners + abstract getChildren()).
 * 
 * 
 * @version $Revision: 954 $ - $Date: 2011-06-07 16:23:31 +0200 (Tue, 07 Jun 2011) $
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
