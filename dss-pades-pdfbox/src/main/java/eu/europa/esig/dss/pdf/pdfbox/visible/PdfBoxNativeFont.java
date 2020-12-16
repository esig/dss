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
package eu.europa.esig.dss.pdf.pdfbox.visible;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.AbstractDSSFont;
import eu.europa.esig.dss.pades.DSSNativeFont;
import org.apache.pdfbox.pdmodel.font.PDFont;

import java.awt.*;

/**
 * The PDFBox native implementation of a Font
 */
public class PdfBoxNativeFont extends AbstractDSSFont implements DSSNativeFont<PDFont> {

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
		throw new DSSException("PdfBoxNativeFont.class can be used only with PdfBoxNativeObjectFactory!");
	}

}
