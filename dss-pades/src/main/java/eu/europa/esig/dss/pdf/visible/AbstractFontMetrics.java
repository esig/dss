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
package eu.europa.esig.dss.pdf.visible;

import eu.europa.esig.dss.pdf.AnnotationBox;

/**
 * Contains methods for dealing with textual visual signature creation
 */
public abstract class AbstractFontMetrics {
	
	/**
	 * Returns an array of strings, divided by a new line character
	 * 
	 * @param text {@link String} original text to get lines from
	 * @return an array of {@link String}s
	 */
	public String[] getLines(String text) {
		return text.split("\\r?\\n");
	}

	/**
	 * Computes a text boundary box
	 * 
	 * @param text {@link String} the original text to get Dimension for
	 * @param fontSize the size of a font
	 * @param padding the padding between text and its boundaries
	 * @return {@link AnnotationBox} of the text
	 */
	public AnnotationBox computeTextBoundaryBox(String text, float fontSize, float padding) {
		String[] lines = getLines(text);
		float width = 0;
		for (String line : lines) {
			float lineWidth = getWidth(line, fontSize);
			if (lineWidth > width) {
				width = lineWidth;
			}
		}
		float doublePadding = padding*2;
		width += doublePadding;
		float strHeight = getHeight(text, fontSize);
		float height = (strHeight * lines.length) + doublePadding;
		
		return new AnnotationBox(0, 0, width, height);
	}
	
	/**
	 * Computes a width for a string of a given size
	 * 
	 * @param str {@link String} to get width of
	 * @param size of a string
	 * @return string width
	 */
	public abstract float getWidth(String str, float size);

	/**
	 * Computes a height for a string of a given size
	 * 
	 * @param str {@link String} to get height of
	 * @param size of a string
	 * @return string width
	 */
	public abstract float getHeight(String str, float size);

}
