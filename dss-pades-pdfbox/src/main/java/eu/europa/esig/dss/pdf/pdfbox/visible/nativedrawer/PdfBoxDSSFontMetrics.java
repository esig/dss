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

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pdf.visible.AbstractDSSFontMetrics;
import org.apache.pdfbox.pdmodel.font.PDFont;

import java.io.IOException;

/**
 * Contains font metrics for a PDFBox font
 */
public class PdfBoxDSSFontMetrics extends AbstractDSSFontMetrics {

	/** PdfBox font */
	private final PDFont pdFont;

	/**
	 * Default constructor
	 *
	 * @param pdFont {@link PDFont}
	 */
	public PdfBoxDSSFontMetrics(PDFont pdFont) {
		this.pdFont = pdFont;
	}

	@Override
	public float getWidth(String str, float size) {
		try {
			return pdFont.getStringWidth(str) / 1000 * size;
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to compute string width! Reason : %s", e.getMessage()), e);
		}
	}

	@Override
	public float getHeight(String str, float size) {
		try {
			return pdFont.getBoundingBox().getHeight() / 1000 * size;
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to compute string height! Reason : %s", e.getMessage()), e);
		}
	}

}
