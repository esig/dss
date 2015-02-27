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

package eu.europa.ec.markt.dss.commons.swing;

import java.awt.Component;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Rectangle;
import java.awt.geom.AffineTransform;

import javax.swing.Icon;

/**
 * The RotatedIcon allows you to change the orientation of an Icon by rotating the Icon before it is painted. This class
 * supports the following orientations:
 * 
 * <ul>
 * <li>DOWN - rotated 90 degrees
 * <li>UP (default) - rotated -90 degrees
 * <li>UPSIDE_DOWN - rotated 180 degrees
 * <li>ABOUT_CENTER - the icon is rotated a specfic angle about its center. The angle of rotation is specified when the
 * class is created.
 * </ul>
 */
public class RotatedIcon implements Icon {
    /**
     * 
     * TODO
     * 
     * <p>
     * DISCLAIMER: Project owner DG-MARKT.
     * 
     * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
     * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
     */
    public enum Rotate {
        DOWN, UP, UPSIDE_DOWN, ABOUT_CENTER;
    }

    private Icon icon;

    private Rotate rotate;

    private double angle;

    /**
     * Convenience constructor to create a RotatedIcon that is rotated DOWN.
     * 
     * @param icon the Icon to rotate
     */
    public RotatedIcon(final Icon icon) {
        this(icon, Rotate.UP);
    }

    /**
     * Create a RotatedIcon. The icon will rotate about its center. This constructor will automatically set the Rotate
     * enum to ABOUT_CENTER. For rectangular icons the icon will be clipped before the rotation to make sure it doesn't
     * paint over the rest of the component.
     * 
     * @param icon the Icon to rotate
     * @param angle the angle of rotation
     */
    public RotatedIcon(final Icon icon, final double angle) {
        this(icon, Rotate.ABOUT_CENTER);
        this.angle = angle;
    }

    /**
     * Create a RotatedIcon
     * 
     * @param icon the Icon to rotate
     * @param rotate the direction of rotation
     */
    public RotatedIcon(final Icon icon, final Rotate rotate) {
        this.icon = icon;
        this.rotate = rotate;
    }

    /**
     * Gets the angle of rotation. Only use for Rotate.ABOUT_CENTER.
     * 
     * @return the angle of rotation
     */
    public double getAngle() {
        return angle;
    }

    /**
     * Gets the Icon to be rotated
     * 
     * @return the Icon to be rotated
     */
    public Icon getIcon() {
        return icon;
    }

    /**
     * Gets the height of this icon.
     * 
     * @return the height of the icon in pixels.
     */
    @Override
    public int getIconHeight() {
        if (rotate == Rotate.UPSIDE_DOWN || rotate == Rotate.ABOUT_CENTER) {
            return icon.getIconHeight();
        } else {
            return icon.getIconWidth();
        }
    }

    /**
     * Gets the width of this icon.
     * 
     * @return the width of the icon in pixels.
     */
    @Override
    public int getIconWidth() {
        if (rotate == Rotate.UPSIDE_DOWN || rotate == Rotate.ABOUT_CENTER) {
            return icon.getIconWidth();
        } else {
            return icon.getIconHeight();
        }
    }

    /**
     * Gets the Rotate enum which indicates the direction of rotation
     * 
     * @return the Rotate enum
     */
    public Rotate getRotate() {
        return rotate;
    }

    /**
     * Paint the icons of this compound icon at the specified location
     * 
     * @param c The component on which the icon is painted
     * @param g the graphics context
     * @param x the X coordinate of the icon's top-left corner
     * @param y the Y coordinate of the icon's top-left corner
     */
    @Override
    public void paintIcon(final Component c, final Graphics g, final int x, final int y) {
        final Graphics2D g2 = (Graphics2D) g.create();

        final int cWidth = icon.getIconWidth() / 2;
        final int cHeight = icon.getIconHeight() / 2;
        final int xAdjustment = (icon.getIconWidth() % 2) == 0 ? 0 : -1;
        final int yAdjustment = (icon.getIconHeight() % 2) == 0 ? 0 : -1;

        if (rotate == Rotate.DOWN) {
            g2.translate(x + cHeight, y + cWidth);
            g2.rotate(Math.toRadians(90));
            icon.paintIcon(c, g2, -cWidth, yAdjustment - cHeight);
        } else if (rotate == Rotate.UP) {
            g2.translate(x + cHeight, y + cWidth);
            g2.rotate(Math.toRadians(-90));
            icon.paintIcon(c, g2, xAdjustment - cWidth, -cHeight);
        } else if (rotate == Rotate.UPSIDE_DOWN) {
            g2.translate(x + cWidth, y + cHeight);
            g2.rotate(Math.toRadians(180));
            icon.paintIcon(c, g2, xAdjustment - cWidth, yAdjustment - cHeight);
        } else if (rotate == Rotate.ABOUT_CENTER) {
            final Rectangle r = new Rectangle(x, y, icon.getIconWidth(), icon.getIconHeight());
            g2.setClip(r);
            final AffineTransform original = g2.getTransform();
            final AffineTransform at = new AffineTransform();
            at.concatenate(original);
            at.rotate(Math.toRadians(angle), x + cWidth, y + cHeight);
            g2.setTransform(at);
            icon.paintIcon(c, g2, x, y);
            g2.setTransform(original);
        }
    }
}
