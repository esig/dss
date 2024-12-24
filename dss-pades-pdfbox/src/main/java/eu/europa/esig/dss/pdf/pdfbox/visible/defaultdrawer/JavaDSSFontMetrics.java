/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pdf.pdfbox.visible.defaultdrawer;

import eu.europa.esig.dss.pdf.visible.AbstractDSSFontMetrics;

import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.image.BufferedImage;

/**
 * Contains font metrics for a Java font
 */
public class JavaDSSFontMetrics extends AbstractDSSFontMetrics {

	/** The Java font to be used */
	private Font javaFont;

	/** Cached instance of font metrics */
	private FontMetrics fontMetrics;

	/**
	 * Default constructor
	 *
	 * @param javaFont {@link Font}
	 */
	public JavaDSSFontMetrics(Font javaFont) {
		this.javaFont = javaFont;
	}

	private FontMetrics getFontMetrics(float fontSize) {
		if (fontMetrics != null && javaFont.getSize() == fontSize) {
			return fontMetrics;
		}
		this.javaFont = javaFont.deriveFont(fontSize);
		BufferedImage img = new BufferedImage(1, 1, BufferedImage.TYPE_INT_RGB);
		Graphics g = img.getGraphics();
		g.setFont(javaFont);
		this.fontMetrics = g.getFontMetrics(javaFont);
		g.dispose();
		return fontMetrics;
	}

	@Override
	public float getWidth(String str, float size) {
		return getFontMetrics(size).stringWidth(str);
	}

	@Override
	public float getHeight(String str, float size) {
		return getFontMetrics(size).getHeight() / 1.05f; // default height is too large
	}

	/**
	 * Returns the max ascent for the given font {@code size}
	 *
	 * @param size font size
	 * @return max ascent
	 */
	public float getMaxAscent(float size) {
		return getFontMetrics(size).getMaxAscent();
	}

}
