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

import com.lowagie.text.pdf.PRStream;
import com.lowagie.text.pdf.PdfBoolean;
import com.lowagie.text.pdf.PdfDate;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfIndirectReference;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfNull;
import com.lowagie.text.pdf.PdfNumber;
import com.lowagie.text.pdf.PdfObject;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfString;
import eu.europa.esig.dss.pdf.PdfArray;
import eu.europa.esig.dss.pdf.PdfDict;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Date;
import java.util.Objects;
import java.util.Set;

/**
 * The IText (OpenPDF) implementation of {@code eu.europa.esig.dss.pdf.PdfDict}
 */
class ITextPdfDict implements eu.europa.esig.dss.pdf.PdfDict {

	private static final Logger LOG = LoggerFactory.getLogger(ITextPdfDict.class);

	/** The OpenPDF object */
	private PdfDictionary wrapped;

	/**
	 * Default constructor
	 *
	 * @param wrapped {@link PdfDictionary}
	 */
	public ITextPdfDict(PdfDictionary wrapped) {
		Objects.requireNonNull(wrapped, "Pdf dictionary shall be provided!");
		this.wrapped = wrapped;
	}

	@Override
	public PdfDict getAsDict(String name) {
		PdfObject directObject = wrapped.getDirectObject(new PdfName(name));
		if (directObject != null && directObject instanceof PdfDictionary) {
			return new ITextPdfDict((PdfDictionary) directObject);
		}
		return null;
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
	public byte[] getBinariesValue(String name) {
		PdfObject val = wrapped.get(new PdfName(name));
		if (val == null) {
			return null;
		} else if (val instanceof PdfString) {
			PdfString pdfString = (PdfString) val;
			return pdfString.getOriginalBytes();
		}
		return val.getBytes();
	}

	@Override
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
			return pdfString.toUnicodeString();
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

	@Override
	public Number getNumberValue(String name) {
		PdfNumber pdfNumber = wrapped.getAsNumber(new PdfName(name));
		if (pdfNumber != null) {
			return pdfNumber.floatValue();
		}
		return null;
	}

	@Override
	public Object getObject(String name) {
		PdfObject pdfObject = wrapped.getDirectObject(new PdfName(name));
		if (pdfObject == null) {
			return null;
		} else if (pdfObject instanceof PdfDictionary) {
			return getAsDict(name);
		} else if (pdfObject instanceof com.lowagie.text.pdf.PdfArray) {
			return getAsArray(name);
		} else if (pdfObject instanceof PdfString) {
			return getStringValue(name);
		} else if (pdfObject instanceof PdfName) {
			return getNameValue(name);
		} else if (pdfObject instanceof PdfNumber) {
			return getNumberValue(name);
		} else if (pdfObject instanceof PdfBoolean) {
			return ((PdfBoolean) pdfObject).booleanValue();
		} else if (pdfObject instanceof PdfNull) {
			return null;
		} else {
			LOG.warn("Unable to process an entry with name '{}' of type '{}'.", name, pdfObject.getClass());
		}
		return null;
	}

	@Override
	public Long getObjectNumber(String name) {
		PdfIndirectReference indirectObject = wrapped.getAsIndirectObject(new PdfName(name));
		if (indirectObject != null) {
			return Long.valueOf(indirectObject.getNumber());
		}
		return null;
	}

	@Override
	public byte[] getStreamBytes() throws IOException {
		if (wrapped instanceof PRStream) {
			return PdfReader.getStreamBytes((PRStream) wrapped);
		}
		return null;
	}

}
