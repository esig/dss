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
package eu.europa.esig.dss.pdf.pdfbox.visible;

import eu.europa.esig.dss.pades.AbstractDSSFont;
import eu.europa.esig.dss.pades.DSSNativeFont;
import org.apache.pdfbox.pdmodel.font.PDFont;

import java.awt.Font;
import java.util.Objects;

/**
 * The PDFBox native implementation of a Font
 */
public class PdfBoxNativeFont extends AbstractDSSFont implements DSSNativeFont<PDFont> {

	private static final long serialVersionUID = -7122453492359548221L;

	/** PDFBox font */
	private final PDFont pdFont;

	/**
	 * Default constructor
	 *
	 * @param pdFont {@link PDFont}
	 */
	public PdfBoxNativeFont(PDFont pdFont) {
		this.pdFont = pdFont;
	}

	@Override
	public PDFont getFont() {
		return pdFont;
	}

	@Override
	public Font getJavaFont() {
		throw new UnsupportedOperationException("PdfBoxNativeFont.class can be used only with PdfBoxNativeObjectFactory!");
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		PdfBoxNativeFont that = (PdfBoxNativeFont) o;
		return Objects.equals(pdFont, that.pdFont);
	}

	@Override
	public int hashCode() {
		return Objects.hashCode(pdFont);
	}

}
