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
import com.lowagie.text.pdf.PdfBoolean;
import com.lowagie.text.pdf.PdfDate;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfIndirectReference;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfNull;
import com.lowagie.text.pdf.PdfNumber;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfString;
import eu.europa.esig.dss.pdf.PdfArray;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfObject;
import eu.europa.esig.dss.pdf.PdfSimpleObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.Objects;
import java.util.Set;

/**
 * The IText (OpenPDF) implementation of {@code eu.europa.esig.dss.pdf.PdfDict}
 */
class ITextPdfDict implements eu.europa.esig.dss.pdf.PdfDict {

	private static final Logger LOG = LoggerFactory.getLogger(ITextPdfDict.class);

	/** The OpenPDF object */
	private final PdfDictionary wrapped;

	/** Parent object */
	private final PdfObject parent;

	/**
	 * Constructor to create a new empty dictionary
	 */
	public ITextPdfDict() {
		this(new PdfDictionary(), null);
	}

	/**
	 * Default constructor
	 *
	 * @param wrapped {@link PdfDictionary}
	 */
	public ITextPdfDict(final PdfDictionary wrapped) {
		this(wrapped, null);
	}

	/**
	 * Constructor with a parent provided
	 *
	 * @param wrapped {@link PdfDictionary}
	 * @param parent {@link PdfObject}
	 */
	public ITextPdfDict(final PdfDictionary wrapped, final PdfObject parent) {
		Objects.requireNonNull(wrapped, "Pdf dictionary shall be provided!");
		this.wrapped = wrapped;
		this.parent = parent;
	}

	@Override
	public PdfDictionary getValue() {
		return wrapped;
	}

	@Override
	public PdfObject getParent() {
		return parent;
	}

	@Override
	public PdfDict getAsDict(String name) {
		com.lowagie.text.pdf.PdfObject directObject = wrapped.getDirectObject(new PdfName(name));
		if (directObject instanceof PdfDictionary) {
			return new ITextPdfDict((PdfDictionary) directObject, this);
		}
		return null;
	}

	@Override
	public PdfArray getAsArray(String name) {
		com.lowagie.text.pdf.PdfArray asArray = wrapped.getAsArray(new PdfName(name));
		if (asArray == null) {
			return null;
		} else {
			return new ITextPdfArray(asArray, this);
		}
	}

	@Override
	public byte[] getBinariesValue(String name) {
		com.lowagie.text.pdf.PdfObject val = wrapped.get(new PdfName(name));
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
		com.lowagie.text.pdf.PdfObject pdfObject = wrapped.get(new PdfName(name));
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
			return pdfNumber.doubleValue();
		}
		return null;
	}

	@Override
	public PdfObject getObject(String name) {
		com.lowagie.text.pdf.PdfObject pdfObject = wrapped.getDirectObject(new PdfName(name));
		if (pdfObject == null) {
			return null;
		} else if (pdfObject instanceof PdfDictionary) {
			return getAsDict(name);
		} else if (pdfObject instanceof com.lowagie.text.pdf.PdfArray) {
			return getAsArray(name);
		} else if (pdfObject instanceof PdfString) {
			return new PdfSimpleObject(getStringValue(name), this);
		} else if (pdfObject instanceof PdfName) {
			return new PdfSimpleObject(getNameValue(name), this);
		} else if (pdfObject instanceof PdfNumber) {
			return new PdfSimpleObject(getNumberValue(name), this);
		} else if (pdfObject instanceof PdfBoolean) {
			return new PdfSimpleObject(((PdfBoolean) pdfObject).booleanValue(), this);
		} else if (pdfObject instanceof PdfNull) {
			return null;
		} else {
			LOG.warn("Unable to process an entry with name '{}' of type '{}'.", name, pdfObject.getClass());
		}
		return null;
	}

	@Override
	@Deprecated
	public Long getObjectNumber(String name) {
		ITextObjectKey objectKey = getObjectKey(name);
		if (objectKey != null) {
			return objectKey.getNumber();
		}
		return null;
	}

	@Override
	public ITextObjectKey getObjectKey(String name) {
		PdfIndirectReference indirectObject = wrapped.getAsIndirectObject(new PdfName(name));
		if (indirectObject != null) {
			return new ITextObjectKey(indirectObject);
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

	@Override
	public InputStream createRawInputStream() throws IOException {
		if (wrapped instanceof PRStream) {
			byte[] streamBytesRaw = PdfReader.getStreamBytesRaw((PRStream) wrapped);
			return new ByteArrayInputStream(streamBytesRaw);
		}
		return null;
	}

	@Override
	public long getRawStreamSize() throws IOException {
		if (wrapped instanceof PRStream) {
			byte[] streamBytesRaw = PdfReader.getStreamBytesRaw((PRStream) wrapped);
			return streamBytesRaw.length;
		}
		return -1;
	}

	@Override
	public void setPdfObjectValue(String key, PdfObject pdfObject) {
		Object value = pdfObject.getValue();
		if (!(value instanceof com.lowagie.text.pdf.PdfObject)) {
			throw new UnsupportedOperationException("pdfObject argument shall be of PdfObject type!");
		}
		wrapped.put(new PdfName(key), (com.lowagie.text.pdf.PdfObject) value);
	}

	@Override
	public void setNameValue(String key, String value) {
		wrapped.put(new PdfName(key), new PdfName(value));
	}

	@Override
	public void setStringValue(String key, String value) {
		wrapped.put(new PdfName(key), new PdfString(value));
	}

	@Override
	public void setIntegerValue(String key, Integer value) {
		wrapped.put(new PdfName(key), new PdfNumber(value));
	}

	@Override
	public void setDirect(boolean direct) {
		// not supported
	}

	@Override
	public boolean match(PdfDict pdfDict) {
		if (!(pdfDict instanceof ITextPdfDict)) {
			throw new UnsupportedOperationException("pdfDict argument shall be of ITextPdfDict type!");
		}
		ITextPdfDict iTextPdfDict = (ITextPdfDict) pdfDict;
		for (PdfName key : iTextPdfDict.wrapped.getKeys()) {
			com.lowagie.text.pdf.PdfObject targetObject = iTextPdfDict.wrapped.get(key);
			com.lowagie.text.pdf.PdfObject currentObject = wrapped.get(key);
			// TODO : equals not implemented for all ?
			if (targetObject != null && !targetObject.equals(currentObject)) {
				return false;
			}
		}
		return true;
	}

}
