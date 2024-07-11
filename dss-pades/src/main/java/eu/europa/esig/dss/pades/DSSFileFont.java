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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

import java.awt.Font;
import java.awt.FontFormatException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

/**
 * The Font created from a file
 */
public class DSSFileFont extends AbstractDSSFont {

	private static final long serialVersionUID = -2631152291035404442L;

	/** The default font name */
	private static final String DEFAULT_FONT_NAME = "PTSerifRegular.ttf";

	/** The default font resource */
	private static final DSSDocument DEFAULT_FONT = new InMemoryDocument(
			SignatureImageTextParameters.class.getResourceAsStream("/fonts/" + DEFAULT_FONT_NAME), DEFAULT_FONT_NAME);

	/** The font file extension */
	private static final String DEFAULT_FONT_EXTENSION = ".ttf";

	/** The font document */
	private DSSDocument fileFont;

	/** Java implementation of the font */
	private Font javaFont;

	/**
	 * Defines whether only a subset of used glyphs should be embedded to a PDF,
	 * when a font file is used with a text information defined within a signature field.
	 *
	 * DEFAULT : FALSE (all glyphs from a font file are embedded to a PDF document)
	 *
	 * NOTE : this parameter will not take effect for {@code DefaultPdfBoxVisibleSignatureDrawer}
	 */
	private boolean embedFontSubset = false;

	/**
	 * Initializes the default {@code DSSFileFont}
	 *
	 * @return {@link DSSFileFont}
	 */
	public static DSSFileFont initializeDefault() {
		return new DSSFileFont(DEFAULT_FONT);
	}

	/**
	 * Constructor to load the font from InputStream
	 *
	 * @param inputStream {@link InputStream} containing a font
	 */
	public DSSFileFont(InputStream inputStream) {
		this(new InMemoryDocument(inputStream));
	}

	/**
	 * Constructor to load the font from DSSDocument
	 *
	 * @param dssDocument {@link DSSDocument} containing a font
	 */
	public DSSFileFont(DSSDocument dssDocument) {
		this(dssDocument, DEFAULT_TEXT_SIZE);
	}

	/**
	 * Constructor to load the font from DSSDocument with a size
	 *
	 * @param dssDocument {@link DSSDocument} containing a font
	 * @param size value of the font
	 */
	public DSSFileFont(DSSDocument dssDocument, float size) {
		Objects.requireNonNull(dssDocument, "Font document cannot be null!");
		if (dssDocument instanceof DigestDocument) {
			throw new IllegalArgumentException("DigestDocument cannot be used as a font document!");
		}

		this.fileFont = dssDocument;
		this.size = size;
		initFontName(dssDocument);
	}
	
	private void initFontName(DSSDocument fileFont) {
		if (Utils.isStringBlank(fileFont.getName())) {
			fileFont.setName(DSSUtils.getMD5Digest(DSSUtils.toByteArray(fileFont)) + DEFAULT_FONT_EXTENSION);
		}
	}
	
	@Override
	public Font getJavaFont() {
		if (javaFont == null) {
			javaFont = deriveJavaFont();
		}
		return javaFont;
	}
	
	private Font deriveJavaFont() {
		try (InputStream is = fileFont.openStream()) {
			Font font = Font.createFont(Font.TRUETYPE_FONT, is);
			return font.deriveFont(size);
		} catch (IOException | FontFormatException e) {
			throw new DSSException(String.format("The Java font cannot be instantiated. Reason : %s", e.getMessage()), e);
		}
	}

	/**
	 * Gets font's content InputStream
	 *
	 * @return {@link InputStream} of the font's document
	 */
	public InputStream getInputStream() {
		return fileFont.openStream();
	}

	/**
	 * Gets name of the font document
	 *
	 * @return {@link String} font document name
	 */
	public String getName() {
		return fileFont.getName();
	}

	/**
	 * Sets whether only a subset of used glyphs should be embedded to a PDF, when a {@code DSSFileFont} is used.
	 *
	 * When set to TRUE, only the used glyphs will be embedded to a font.
	 * When set to FALSE, all glyphs from a font will be embedded to a PDF.
	 *
	 * DEFAULT : FALSE (the whole font file is embedded to a PDF)
	 *
	 * NOTE : this parameter will not take effect for {@code DefaultPdfBoxVisibleSignatureDrawer}
	 *
	 * @param embedFontSubset whether only a subset of used glyphs should be embedded to a PDF
	 */
	public void setEmbedFontSubset(boolean embedFontSubset) {
		this.embedFontSubset = embedFontSubset;
	}

	/**
	 * This method returns whether only a font subset should be included into a PDF
	 *
	 * @return TRUE if a font subset should be included to a PDF, FALSE if the whole font file
	 */
	public boolean isEmbedFontSubset() {
		return embedFontSubset;
	}

}
