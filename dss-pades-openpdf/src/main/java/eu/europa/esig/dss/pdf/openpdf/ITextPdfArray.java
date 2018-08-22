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
package eu.europa.esig.dss.pdf.openpdf;

import java.io.IOException;

import com.lowagie.text.pdf.PRStream;
import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfNumber;
import com.lowagie.text.pdf.PdfReader;

class ITextPdfArray implements eu.europa.esig.dss.pdf.PdfArray {

	private PdfArray wrapped;

	ITextPdfArray(PdfArray wrapped) {
		this.wrapped = wrapped;
	}

	@Override
	public byte[] getBytes(int i) throws IOException {
		return PdfReader.getStreamBytes((PRStream) wrapped.getAsStream(i));
	}

	@Override
	public int getInt(int i) throws IOException {
		PdfNumber number = wrapped.getAsNumber(i);
		if (number != null) {
			return number.intValue();
		}
		return 0;
	}

	@Override
	public int size() {
		return wrapped.size();
	}

}
