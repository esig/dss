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
package eu.europa.esig.dss.applet.view;

import java.awt.Cursor;
import java.awt.Graphics;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;

import javax.swing.JLabel;
import javax.swing.JPanel;

import eu.europa.esig.dss.applet.util.ComponentFactory;
import eu.europa.esig.dss.applet.util.ResourceUtils;

/**
 * 
 * TODO
 * 
 *
 *
 * 
 *
 *
 */
@SuppressWarnings("serial")
public class WaitingGlassPanel extends JPanel {

    /**
     * 
     * The default constructor for WaitingGlassPanel.
     */
    public WaitingGlassPanel() {
        final JLabel label = ComponentFactory.createLabel(ResourceUtils.getI18n("PLEASE_WAIT"), ComponentFactory.iconWait());
        this.setCursor(new Cursor(Cursor.WAIT_CURSOR));
        this.setOpaque(false);

        this.setLayout(new GridBagLayout());
        this.add(label, new GridBagConstraints());
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.swing.JComponent#paintComponent(java.awt.Graphics)
     */
    @Override
    protected void paintComponent(final Graphics g) {
        g.setColor(new java.awt.Color(255, 255, 255, 150));
        g.fillRect(0, 0, getWidth() - 1, getHeight() - 1);
        super.paintComponent(g);
    }
}
