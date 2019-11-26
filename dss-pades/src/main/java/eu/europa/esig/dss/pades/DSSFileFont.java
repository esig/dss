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
import java.awt.FontFormatException;
import java.io.IOException;
import java.io.InputStream;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

public class DSSFileFont extends AbstractDSSFont {
	
	private static final String DEFAULT_FONT_NAME = "PTSerifRegular.ttf";
	private static final DSSDocument DEFAULT_FONT = new InMemoryDocument(
			SignatureImageTextParameters.class.getResourceAsStream("/fonts/" + DEFAULT_FONT_NAME), DEFAULT_FONT_NAME);
	
	private static final String DEFAULT_FONT_EXTENSION = ".ttf";
	
	private DSSDocument fileFont;
	
	public static DSSFileFont initializeDefault() {
		return new DSSFileFont(DEFAULT_FONT);
	}
	
	public DSSFileFont(InputStream inputStream) {
		this(new InMemoryDocument(inputStream));
	}
	
	public DSSFileFont(DSSDocument dssDocument) {
		this(dssDocument, DEFAULT_TEXT_SIZE);
	}
	
	public DSSFileFont(DSSDocument dssDocument, float size) {
		this.fileFont = dssDocument;
		this.size = size;
		initFontName(dssDocument);
		initJavaFont(dssDocument);
	}
	
	private void initFontName(DSSDocument fileFont) {
		if (Utils.isStringBlank(fileFont.getName())) {
			fileFont.setName(DSSUtils.getMD5Digest(DSSUtils.toByteArray(fileFont)) + DEFAULT_FONT_EXTENSION);
		}
	}
	
	private void initJavaFont(DSSDocument fileFont) {
		try (InputStream is = fileFont.openStream()) {
			Font javaFont = Font.createFont(Font.TRUETYPE_FONT, is);
			this.javaFont = javaFont.deriveFont(size);
		} catch (IOException | FontFormatException e) {
			throw new DSSException("The assigned font cannot be initialized", e);
		}
	}

	@Override
	public InputStream getInputStream() {
		return fileFont.openStream();
	}

	@Override
	public String getName() {
		return fileFont.getName();
	}

	@Override
	public void setSize(float size) {
		this.size = size;
	}

	@Override
	public boolean isLogicalFont() {
		return false;
	}

}
