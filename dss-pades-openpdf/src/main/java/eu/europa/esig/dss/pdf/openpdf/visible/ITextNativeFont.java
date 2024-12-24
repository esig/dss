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
package eu.europa.esig.dss.pdf.openpdf.visible;

import com.lowagie.text.pdf.BaseFont;
import com.lowagie.text.pdf.DefaultFontMapper;
import eu.europa.esig.dss.pades.AbstractDSSFont;
import eu.europa.esig.dss.pades.DSSNativeFont;

import java.awt.Font;
import java.util.Objects;

/**
 * The IText (OpenPDF) native font
 */
public class ITextNativeFont extends AbstractDSSFont implements DSSNativeFont<BaseFont> {

	private static final long serialVersionUID = 6440459797629392086L;

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

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		ITextNativeFont that = (ITextNativeFont) o;
		return Objects.equals(baseFont, that.baseFont);
	}

	@Override
	public int hashCode() {
		return Objects.hashCode(baseFont);
	}

}
