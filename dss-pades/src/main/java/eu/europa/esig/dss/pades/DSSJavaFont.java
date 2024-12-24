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
package eu.europa.esig.dss.pades;

import java.awt.Font;
import java.util.Objects;

/**
 * Represent the JAVA implementation of the DSSFont
 */
public class DSSJavaFont extends AbstractDSSFont {

	private static final long serialVersionUID = 5555902178825682245L;

	/** The default font style */
	private static final int DEFAULT_FONT_STYLE = Font.PLAIN;

	/** The Java font */
	private Font javaFont;

	/**
	 * Default constructor
	 *
	 * @param javaFont {@link Font}
	 */
	public DSSJavaFont(Font javaFont) {
		this.javaFont = javaFont;
		this.size = javaFont.getSize();
	}

	/**
	 * Constructor from font's name
	 *
	 * @param fontName {@link String} name of the Java font to load
	 */
	public DSSJavaFont(String fontName) {
		this.javaFont = new Font(fontName, DEFAULT_FONT_STYLE, (int) DEFAULT_TEXT_SIZE);
	}

	/**
	 * Constructor from font's name with size
	 *
	 * @param fontName {@link String} name of the Java font to load
	 * @param size value for the font
	 */
	public DSSJavaFont(String fontName, int size) {
		this.size = size;
		this.javaFont = new Font(fontName, DEFAULT_FONT_STYLE, size);
	}

	/**
	 * Constructor from font's name with a style and size
	 *
	 * @param fontName {@link String} name of the Java font to load
	 * @param style value for the font
	 * @param size value for the font
	 */
	public DSSJavaFont(String fontName, int style, int size) {
		this.size = size;
		this.javaFont = new Font(fontName, style, size);
	}

	@Override
	public Font getJavaFont() {
		return javaFont;
	}

	/**
	 * Gets the name of the font
	 *
	 * @return {@link String}
	 */
	public String getName() {
		return javaFont.getFontName();
	}

	@Override
	public void setSize(float size) {
		super.setSize(size);
		this.javaFont = javaFont.deriveFont(size);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		DSSJavaFont that = (DSSJavaFont) o;
		return Objects.equals(javaFont, that.javaFont);
	}

	@Override
	public int hashCode() {
		return Objects.hashCode(javaFont);
	}

}
