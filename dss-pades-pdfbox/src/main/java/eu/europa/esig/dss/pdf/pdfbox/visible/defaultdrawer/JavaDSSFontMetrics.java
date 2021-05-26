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
package eu.europa.esig.dss.pdf.pdfbox.visible.defaultdrawer;

import eu.europa.esig.dss.pdf.visible.AbstractDSSFontMetrics;

import java.awt.*;
import java.awt.image.BufferedImage;

/**
 * Contains font metrics for a Java font
 */
public class JavaDSSFontMetrics extends AbstractDSSFontMetrics {

	/** Java FontMetrics */
	private final FontMetrics fontMetrics;

	/**
	 * Default constructor
	 *
	 * @param javaFont {@link Font}
	 */
	public JavaDSSFontMetrics(Font javaFont) {
		this.fontMetrics = getFontMetrics(javaFont);
	}

	private static FontMetrics getFontMetrics(Font font) {
		BufferedImage img = new BufferedImage(1, 1, BufferedImage.TYPE_INT_RGB);
		Graphics g = img.getGraphics();
		g.setFont(font);
		FontMetrics fontMetrics = g.getFontMetrics(font);
		g.dispose();
		return fontMetrics;
	}

	@Override
	public float getWidth(String str, float size) {
		return fontMetrics.stringWidth(str);
	}

	@Override
	public float getHeight(String str, float size) {
		return fontMetrics.getHeight() / 1.05f; // default height is too large
	}

}
