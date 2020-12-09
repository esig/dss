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
package eu.europa.esig.dss.pdf.openpdf.visible;

import com.lowagie.text.pdf.BaseFont;
import com.lowagie.text.pdf.DefaultFontMapper;
import eu.europa.esig.dss.pades.AbstractDSSFont;
import eu.europa.esig.dss.pades.DSSNativeFont;

import java.awt.*;

/**
 * The IText (OpenPDF) native font
 */
public class ITextNativeFont extends AbstractDSSFont implements DSSNativeFont<BaseFont> {

	/** The OpenPDF font */
	private final BaseFont baseFont;

	/**
	 * Default constructor
	 *
	 * @param baseFont {@link BaseFont}
	 */
	public ITextNativeFont(BaseFont baseFont) {
		this.baseFont = baseFont;
	}

	@Override
	public BaseFont getFont() {
		return baseFont;
	}

	@Override
	public Font getJavaFont() {
		DefaultFontMapper fontMapper = new DefaultFontMapper();
		return fontMapper.pdfToAwt(baseFont, (int)size);
	}

}
