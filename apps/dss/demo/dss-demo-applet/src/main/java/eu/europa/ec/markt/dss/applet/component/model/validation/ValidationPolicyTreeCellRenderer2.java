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

import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.swing.*;
import javax.swing.tree.DefaultTreeCellRenderer;

/**
 * Paint one tree cell of the validation policy document.
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
@SuppressWarnings("serial")
public class ValidationPolicyTreeCellRenderer2 extends DefaultTreeCellRenderer {

    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(ValidationPolicyTreeCellRenderer2.class);

    private Icon getIconForObject(final Object value) {
        return null;
    }

    private String getLabel(final Object value) {
        if (value instanceof Date) {
            final Date date = (Date) value;
            return getLabel(date);
        } else if (value instanceof TreeNode) {
            final TreeNode node = (TreeNode) value;
            return getLabel(node);
        } else {
            if (value != null) {
                return value.toString();
            } else {
                return null;
            }
        }
    }

    private String getLabel(final Date date) {
        final SimpleDateFormat sdf = new SimpleDateFormat();
        return sdf.format(date);
    }

    private String getLabel(final TreeNode node) {
        return node.getTitle();
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.swing.tree.DefaultTreeCellRenderer#getTreeCellRendererComponent(javax.swing.JTree, java.lang.Object,
     * boolean, boolean, boolean, int, boolean)
     */
    @Override
    public Component getTreeCellRendererComponent(final JTree tree, Object value, final boolean sel, final boolean expanded, final boolean leaf, final int row, final boolean hasFocus) {
        setIcon(null);
        setToolTipText(null);

        String label = getLabel(value);

        super.getTreeCellRendererComponent(tree, label, sel, expanded, leaf, row, hasFocus);

        final Icon newIcon = getIconForObject(value);

        if (newIcon != null) {
            setIcon(newIcon);
        }

        if (getToolTipText() == null || getToolTipText().trim().length() == 0) {
            setToolTipText(getText());
        }

        return this;
    }
}
