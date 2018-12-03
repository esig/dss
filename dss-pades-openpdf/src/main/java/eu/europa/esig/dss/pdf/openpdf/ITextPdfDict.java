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

import java.util.Date;
import java.util.Set;

import com.lowagie.text.pdf.PdfDate;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfObject;
import com.lowagie.text.pdf.PdfString;

import eu.europa.esig.dss.pdf.PdfArray;
import eu.europa.esig.dss.pdf.PdfDict;

class ITextPdfDict implements eu.europa.esig.dss.pdf.PdfDict {

	private PdfDictionary wrapped;

	public ITextPdfDict(PdfDictionary wrapped) {
		if (wrapped == null) {
			throw new IllegalArgumentException();
		}
		this.wrapped = wrapped;
	}

	@Override
	public PdfDict getAsDict(String name) {
		PdfDictionary asDict = wrapped.getAsDict(new PdfName(name));
		if (asDict == null) {
			return null;
		} else {
			return new ITextPdfDict(asDict);
		}
	}

	@Override
	public PdfArray getAsArray(String name) {
		com.lowagie.text.pdf.PdfArray asArray = wrapped.getAsArray(new PdfName(
				name));
		if (asArray == null) {
			return null;
		} else {
			return new ITextPdfArray(asArray);
		}
	}

	@Override
	public byte[] get(String name) {
		PdfObject val = wrapped.get(new PdfName(name));
		if (val == null) {
			return null;
		}
		return val.getBytes();
	}

	@Override
	@SuppressWarnings("unchecked")
	public String[] list() {
		Set<PdfName> keyPdfNames = wrapped.getKeys();
		String[] keys = new String[keyPdfNames.size()];
		PdfName[] array = keyPdfNames.toArray(new PdfName[keyPdfNames.size()]);
		for (int i = 0; i < array.length; i++) {
			keys[i] = PdfName.decodeName(array[i].toString());
		}
		return keys;
	}

	@Override
	public String getStringValue(String key) {
		PdfString pdfString = wrapped.getAsString(new PdfName(key));
		if (pdfString == null) {
			return null;
		} else {
			return pdfString.toString();
		}
	}

	@Override
	public String getNameValue(String key) {
		PdfName pdfName = wrapped.getAsName(new PdfName(key));
		if (pdfName == null) {
			return null;
		} else {
			return PdfName.decodeName(pdfName.toString());
		}
	}

	@Override
	public Date getDateValue(String name) {
		PdfObject pdfObject = wrapped.get(new PdfName(name));
		PdfString s = (PdfString) pdfObject;
		if (s == null) {
			return null;
		}
		return PdfDate.decode(s.toString()).getTime();
	}

}
