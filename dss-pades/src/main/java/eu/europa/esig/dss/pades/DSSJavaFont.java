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
package eu.europa.esig.dss.pades;

import java.awt.Font;

public class DSSJavaFont extends AbstractDSSFont {
	
	private static final int DEFAULT_FONT_STYLE = Font.PLAIN;

	private Font javaFont;
	
	public DSSJavaFont(Font javaFont) {
		this.javaFont = javaFont;
		this.size = javaFont.getSize();
	}
	
	public DSSJavaFont(String fontName) {
		this.javaFont = new Font(fontName, DEFAULT_FONT_STYLE, (int) DEFAULT_TEXT_SIZE);
	}
	
	public DSSJavaFont(String fontName, int size) {
		this.size = size;
		this.javaFont = new Font(fontName, DEFAULT_FONT_STYLE, size);
	}
	
	public DSSJavaFont(String fontName, int style, int size) {
		this.size = size;
		this.javaFont = new Font(fontName, style, size);
	}

	@Override
	public Font getJavaFont() {
		return javaFont;
	}

	public String getName() {
		return javaFont.getFontName();
	}

	@Override
	public void setSize(float size) {
		super.setSize(size);
		this.javaFont = javaFont.deriveFont(size);
	}

}
