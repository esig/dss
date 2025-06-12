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
package eu.europa.esig.dss.pdf.openpdf;

import com.lowagie.text.pdf.PRStream;
import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfBoolean;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfIndirectReference;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfNull;
import com.lowagie.text.pdf.PdfNumber;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfStream;
import com.lowagie.text.pdf.PdfString;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfObject;
import eu.europa.esig.dss.pdf.PdfSimpleObject;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Objects;

/**
 * The IText (OpenPDF) implementation of {@code eu.europa.esig.dss.pdf.PdfArray}
 */
class ITextPdfArray implements eu.europa.esig.dss.pdf.PdfArray {

	private static final Logger LOG = LoggerFactory.getLogger(ITextPdfArray.class);

	/** The OpenPDF object */
	private final PdfArray wrapped;

	/** Parent object */
	private final PdfObject parent;

	/**
	 * Constructor to create a new empty array
	 */
	public ITextPdfArray() {
		this(new PdfArray(), null);
	}

	/**
	 * Default constructor
	 *
	 * @param wrapped {@link PdfArray}
	 */
	public ITextPdfArray(PdfArray wrapped) {
		this(wrapped, null);
	}

	/**
	 * Constructor with a parent provided
	 *
	 * @param wrapped {@link PdfArray}
	 * @param parent {@link PdfObject}
	 */
	public ITextPdfArray(PdfArray wrapped, PdfObject parent) {
		Objects.requireNonNull(wrapped, "Pdf array shall be provided!");
		this.wrapped = wrapped;
		this.parent = parent;
	}

	@Override
	public PdfArray getValue() {
		return wrapped;
	}

	@Override
	public PdfObject getParent() {
		return parent;
	}

	@Override
	public byte[] getStreamBytes(int i) throws IOException {
		return PdfReader.getStreamBytes((PRStream) wrapped.getAsStream(i));
	}

	@Override
	public ITextObjectKey getObjectKey(int i) {
		com.lowagie.text.pdf.PdfObject pdfObject = wrapped.getPdfObject(i);
		if (pdfObject == null) {
			throw new DSSException("The requested PDF object not found!");
		}
		if (pdfObject.isStream()) {
			PdfStream asStream = wrapped.getAsStream(i);
			return new ITextObjectKey(asStream.getIndRef());
		} else if (pdfObject.isIndirect()) {
			PdfIndirectReference asIndirectObject = wrapped.getAsIndirectObject(i);
			return new ITextObjectKey(asIndirectObject);
		}
		return null;
	}

	@Override
	public Number getNumber(int i) {
		PdfNumber number = wrapped.getAsNumber(i);
		if (number != null) {
			if (isInteger(number)) {
				return number.intValue();
			} else {
				return number.doubleValue();
			}
		}
		return null;
	}

	private boolean isInteger(PdfNumber number) {
		return Utils.isStringDigits(new String(number.getBytes()));
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
		com.lowagie.text.pdf.PdfObject directObject = wrapped.getDirectObject(i);
		if (directObject instanceof PdfDictionary) {
			return new ITextPdfDict((PdfDictionary) directObject, this);
		}
		return null;
	}

	@Override
	public PdfObject getObject(int i) {
		com.lowagie.text.pdf.PdfObject directObject = wrapped.getDirectObject(i);
		if (directObject == null) {
			return null;
		}
		if (directObject instanceof PdfDictionary) {
			return getAsDict(i);
		} else if (directObject instanceof com.lowagie.text.pdf.PdfArray) {
			return new ITextPdfArray((com.lowagie.text.pdf.PdfArray) directObject, this);
		} else if (directObject instanceof PdfString) {
			return new PdfSimpleObject(getString(i), this);
		} else if (directObject instanceof PdfName) {
			return new PdfSimpleObject(PdfName.decodeName(directObject.toString()), this);
		} else if (directObject instanceof PdfNumber) {
			return new PdfSimpleObject(getNumber(i), this);
		} else if (directObject instanceof PdfBoolean) {
			return new PdfSimpleObject(((PdfBoolean) directObject).booleanValue(), this);
		} else if (directObject instanceof PdfNull) {
			return null;
		} else {
			LOG.warn("Unable to process an entry on position '{}' of type '{}'.", i, directObject.getClass());
		}
		return null;
	}

	@Override
	public void addObject(PdfObject pdfObject) {
		Object value = pdfObject.getValue();
		if (!(value instanceof com.lowagie.text.pdf.PdfObject)) {
			throw new UnsupportedOperationException("The object to be added shall be of type PdfObject!");
		}
		wrapped.add((com.lowagie.text.pdf.PdfObject) value);
	}

	@Override
	public void setDirect(boolean direct) {
		// not supported
	}

	@Override
	public int size() {
		return wrapped.size();
	}

}
