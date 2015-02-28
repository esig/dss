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
package eu.europa.ec.markt.dss.common;

import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.Action;
import javax.swing.InputMap;
import javax.swing.JComponent;
import javax.swing.KeyStroke;
import javax.swing.ToolTipManager;

/**
 * Small helper class for handling tooltips.
 * 
 *
 *
 */
public abstract class TooltipHelper
{
    private static MouseHandler MOUSE_HANDLER = new MouseHandler();
    private static boolean tooltipMouseHandlerEnabled = true;
    
    /**
     * Unregisters a component at the <code>ToolTipManager</code>.
     * @param c the component to unregister
     */
    public static void unregisterComponentAtTooltipManager(JComponent c) {
        ToolTipManager.sharedInstance().unregisterComponent(c);
    }
    
    /**
     * This Method registers a component at the TooltipManager,
     * to be able to set the initialDelay of the tooltip per componenent.
     * @param c the component to register
     */
    public static void registerComponentAtTooltipManager(JComponent c) {
        InputMap imap = c.getInputMap();

        boolean removeKeyStroke = false;
        KeyStroke[] ks = imap.keys();
        if(ks == null || ks.length == 0) {
            imap.put(KeyStroke.getKeyStroke(KeyEvent.VK_BACK_SLASH, 0), "backSlash");   // dummy
            removeKeyStroke = true;
        }

        ToolTipManager.sharedInstance().registerComponent(c);
//      ToolTipManager.sharedInstance().setDismissDelay(99000);     // set showing time to 99 seconds

        if(removeKeyStroke) {
            imap.remove(KeyStroke.getKeyStroke(KeyEvent.VK_BACK_SLASH, 0));
        }

        c.addMouseListener(MOUSE_HANDLER);
    }

    /**
     * Controls the MouseHandler, wether tooltips should get displayed or not
     * @param b true, if tooltips should be displayed
     */
    public static void enableTooltipMouseHandler(boolean b) {
        tooltipMouseHandlerEnabled = b;
    }
    
    private static class MouseHandler extends MouseAdapter {
        public void mouseEntered(MouseEvent e) {
            if(tooltipMouseHandlerEnabled) {
                JComponent c = (JComponent) e.getComponent();
                Action action = c.getActionMap().get("postTip");
    
                if(action != null) {
                    action.actionPerformed(new ActionEvent(c, ActionEvent.ACTION_PERFORMED, "postTip"));
                }
            }
        }
    }
}