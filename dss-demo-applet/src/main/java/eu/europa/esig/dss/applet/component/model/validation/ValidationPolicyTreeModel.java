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

import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;
import javax.swing.tree.TreePath;

import eu.europa.esig.dss.applet.component.model.XmlDomTreeModelAdapter;
import eu.europa.esig.dss.validation.model.ValidationPolicy;

/**
 * Build the tree model of the validation policy
 *
 *
 *
 *
 *
 *
 */
public class ValidationPolicyTreeModel extends XmlDomTreeModelAdapter {

    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(ValidationPolicyTreeModel.class);

    /**
     * The default constructor for ValidationPolicyTreeModel.
     *
     * @param validationPolicy
     */
    public ValidationPolicyTreeModel(final ValidationPolicy validationPolicy) {
        super(validationPolicy.getDocument(), validationPolicy.getSourceXSD());
    }

    public void fireTreeNodesRemoved(TreePath parentPath, int childIndex, Object child) {
        TreeModelEvent event = new TreeModelEvent(this, parentPath, new int[]{childIndex}, new Object[]{child});
        synchronized (listeners) {
            for (TreeModelListener listener : listeners) {
                listener.treeNodesRemoved(event);
            }
        }
    }

    public void fireTreeInsert(TreePath path, int childIndex, Object child) {
        Object[] children = {child};
        //        int childIndex = this.getIndexOfChild(path.getLastPathComponent(), child);
        int[] indicies = {childIndex};
        TreeModelEvent event = new TreeModelEvent(this, path, indicies, children);
        synchronized (listeners) {
            for (TreeModelListener listener : listeners) {
                listener.treeNodesInserted(event);
            }
        }
    }

    public void fireTreeChanged(TreePath path) {
        TreeModelEvent event = new TreeModelEvent(this, path);
        synchronized (listeners) {
            for (TreeModelListener listener : listeners) {
                listener.treeNodesChanged(event);
            }
        }
    }

    public void fireTreeStructureChanged(TreePath path) {
        TreeModelEvent event = new TreeModelEvent(this, path);
        synchronized (listeners) {
            for (TreeModelListener listener : listeners) {
                listener.treeStructureChanged(event);
            }
        }
    }

}
