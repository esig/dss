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
package eu.europa.esig.dss.pdf.pdfbox;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;

import eu.europa.esig.dss.pdf.PdfArray;
import eu.europa.esig.dss.pdf.PdfDict;

class PdfBoxDict implements PdfDict {

	private COSDictionary wrapped;
	private PDDocument document;

	public PdfBoxDict(COSDictionary wrapped, PDDocument document) {
		this.wrapped = wrapped;
		this.document = document;
	}

	@Override
	public PdfDict getAsDict(String name) {
		COSDictionary dict = (COSDictionary) wrapped.getDictionaryObject(name);
		if (dict == null) {
			return null;
		}
		return new PdfBoxDict(dict, document);
	}

	@Override
	public PdfArray getAsArray(String name) {
		COSArray array = (COSArray) wrapped.getDictionaryObject(name);
		if (array == null) {
			return null;
		}
		return new PdfBoxArray(array, document);
	}

	@Override
	public byte[] get(String name) throws IOException {
		COSBase val = wrapped.getDictionaryObject(name);
		if (val == null) {
			return null;
		}
		if (val instanceof COSString) {
			return ((COSString) val).getBytes();
		}
		if (val instanceof COSName) {
			return ((COSName) val).getName().getBytes();
		}
		throw new IOException(name + " was expected to be a COSString element but was " + val.getClass() + " : " + val);
	}

	@Override
	public String[] list() {
		final Set<COSName> cosNames = wrapped.keySet();
		List<String> result = new ArrayList<String>(cosNames.size());
		for (final COSName cosName : cosNames) {
			final String name = cosName.getName();
			result.add(name);
		}
		return result.toArray(new String[result.size()]);
	}

	@Override
	public String toString() {
		return wrapped.toString();
	}

	@Override
	public String getStringValue(String name) {
		return wrapped.getString(name);
	}

	@Override
	public String getNameValue(String name) {
		return wrapped.getNameAsString(name);
	}

	@Override
	public Date getDateValue(String name) {
		Calendar cal = wrapped.getDate(name);
		if (cal != null) {
			return cal.getTime();
		}
		return null;
	}

}
