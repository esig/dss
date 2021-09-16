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
import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfBoolean;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfIndirectReference;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfNull;
import com.lowagie.text.pdf.PdfNumber;
import com.lowagie.text.pdf.PdfObject;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfStream;
import com.lowagie.text.pdf.PdfString;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pdf.PdfDict;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * The IText (OpenPDF) implementation of {@code eu.europa.esig.dss.pdf.PdfArray}
 */
class ITextPdfArray implements eu.europa.esig.dss.pdf.PdfArray {

	private static final Logger LOG = LoggerFactory.getLogger(ITextPdfArray.class);

	/** The OpenPDF object */
	private PdfArray wrapped;

	/**
	 * Default constructor
	 *
	 * @param wrapped {@link PdfArray}
	 */
	public ITextPdfArray(PdfArray wrapped) {
		this.wrapped = wrapped;
	}

	@Override
	public byte[] getStreamBytes(int i) throws IOException {
		return PdfReader.getStreamBytes((PRStream) wrapped.getAsStream(i));
	}

	@Override
	public Long getObjectNumber(int i) {
		PdfObject pdfObject = wrapped.getPdfObject(i);
		if (pdfObject == null) {
			throw new DSSException("The requested PDF object not found!");
		}
		if (pdfObject.isStream()) {
			PdfStream asStream = wrapped.getAsStream(i);
			return Long.valueOf(asStream.getIndRef().getNumber());
		} else if (pdfObject.isIndirect()) {
			PdfIndirectReference asIndirectObject = wrapped.getAsIndirectObject(i);
			return Long.valueOf(asIndirectObject.getNumber());
		}
		return null;
	}

	@Override
	public Number getNumber(int i) {
		PdfNumber number = wrapped.getAsNumber(i);
		if (number != null) {
			return number.floatValue();
		}
		return null;
	}

	@Override
	public String getString(int i) {
		PdfString pdfString = wrapped.getAsString(i);
		if (pdfString != null) {
			return pdfString.toString();
		}
		return null;
	}

	@Override
	public PdfDict getAsDict(int i) {
		PdfObject directObject = wrapped.getDirectObject(i);
		if (directObject != null && directObject instanceof PdfDictionary) {
			return new ITextPdfDict((PdfDictionary) directObject);
		}
		return null;
	}

	@Override
	public Object getObject(int i) {
		PdfObject directObject = wrapped.getDirectObject(i);
		if (directObject == null) {
			return null;
		}
		if (directObject instanceof PdfDictionary) {
			return getAsDict(i);
		} else if (directObject instanceof com.lowagie.text.pdf.PdfArray) {
			return new ITextPdfArray((com.lowagie.text.pdf.PdfArray) directObject);
		} else if (directObject instanceof PdfString) {
			return getString(i);
		} else if (directObject instanceof PdfName) {
			return PdfName.decodeName(directObject.toString());
		} else if (directObject instanceof PdfNumber) {
			return getNumber(i);
		} else if (directObject instanceof PdfBoolean) {
			return ((PdfBoolean) directObject).booleanValue();
		} else if (directObject instanceof PdfNull) {
			return null;
		} else {
			LOG.warn("Unable to process an entry on position '{}' of type '{}'.", i, directObject.getClass());
		}
		return null;
	}

	@Override
	public int size() {
		return wrapped.size();
	}

}
