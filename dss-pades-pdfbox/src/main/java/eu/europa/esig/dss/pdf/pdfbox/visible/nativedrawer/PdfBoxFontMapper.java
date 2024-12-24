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
package eu.europa.esig.dss.pdf.pdfbox.visible.nativedrawer;

import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;

import java.awt.Font;

/**
 * Maps Java Fonts and PDFBox fonts
 */
public class PdfBoxFontMapper {

	/**
	 * Empty constructor
	 */
	private PdfBoxFontMapper() {
	}

	/**
	 * Gets a PDFBox font by Java font
	 *
	 * @param javaFont {@link Font} java instance of the font
	 * @return {@link PDType1Font}
	 */
	public static PDType1Font getPDFont(Font javaFont) {
		Standard14Fonts.FontName fontName = getFontName(javaFont);
		return new PDType1Font(fontName);
	}

	private static Standard14Fonts.FontName getFontName(Font javaFont) {
		switch (javaFont.getFamily()) {
			case Font.SERIF:
				if (javaFont.isPlain()) {
					return Standard14Fonts.FontName.TIMES_ROMAN;
				} else if (javaFont.isBold()) {
					if (javaFont.isItalic()) {
						return Standard14Fonts.FontName.TIMES_BOLD_ITALIC;
					} else {
						return Standard14Fonts.FontName.TIMES_BOLD;
					}
				} else {
					return Standard14Fonts.FontName.TIMES_ITALIC;
				}
			case Font.SANS_SERIF:
				if (javaFont.isPlain()) {
					return Standard14Fonts.FontName.HELVETICA;
				} else if (javaFont.isBold()) {
					if (javaFont.isItalic()) {
						return Standard14Fonts.FontName.HELVETICA_BOLD_OBLIQUE;
					} else {
						return Standard14Fonts.FontName.HELVETICA_BOLD;
					}
				} else {
					return Standard14Fonts.FontName.HELVETICA_OBLIQUE;
				}
			case Font.MONOSPACED:
				if (javaFont.isPlain()) {
					return Standard14Fonts.FontName.COURIER;
				} else if (javaFont.isBold()) {
					if (javaFont.isItalic()) {
						return Standard14Fonts.FontName.COURIER_BOLD_OBLIQUE;
					} else {
						return Standard14Fonts.FontName.COURIER_BOLD;
					}
				} else {
					return Standard14Fonts.FontName.COURIER_OBLIQUE;
				}
			case Font.DIALOG:
			case Font.DIALOG_INPUT:
				return Standard14Fonts.FontName.SYMBOL;
			default:
				throw new UnsupportedOperationException("The font is not supported! " +
						"Please use DSSFileFont implementation for custom fonts.");
		}
	}

}
