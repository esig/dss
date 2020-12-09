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
package eu.europa.esig.dss.pdf.pdfbox.visible.nativedrawer;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pdf.visible.AbstractFontMetrics;
import org.apache.pdfbox.pdmodel.font.PDFont;

import java.io.IOException;

/**
 * Contains font metrics for a PDFBox font
 */
public class PdfBoxFontMetrics extends AbstractFontMetrics {

	/** PdfBox font */
	private final PDFont pdFont;

	/**
	 * Default constructor
	 *
	 * @param pdFont {@link PDFont}
	 */
	public PdfBoxFontMetrics(PDFont pdFont) {
		this.pdFont = pdFont;
	}

	@Override
	public float getWidth(String str, float size) {
		try {
			return pdFont.getStringWidth(str) / 1000 * size;
		} catch (IOException e) {
			throw new DSSException("Unable to compute string width!");
		}
	}

	@Override
	public float getHeight(String str, float size) {
		try {
			return pdFont.getBoundingBox().getHeight() / 1000 * size;
		} catch (IOException e) {
			throw new DSSException("Unable to compute string height!");
		}
	}

}
