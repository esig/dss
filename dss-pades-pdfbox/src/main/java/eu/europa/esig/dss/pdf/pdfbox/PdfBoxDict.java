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

import eu.europa.esig.dss.pades.validation.PdfObjectKey;
import eu.europa.esig.dss.pdf.PdfArray;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfObject;
import eu.europa.esig.dss.pdf.PdfSimpleObject;
import eu.europa.esig.dss.utils.Utils;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSBoolean;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSFloat;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSNull;
import org.apache.pdfbox.cos.COSNumber;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * The PDFBox implementation of {@code eu.europa.esig.dss.pdf.PdfDict}
 */
class PdfBoxDict implements PdfDict {

	private static final Logger LOG = LoggerFactory.getLogger(PdfBoxDict.class);

	/** The PDFBox object */
	private final COSDictionary wrapped;

	/** The document */
	private final PDDocument document;

	/** Parent object */
	private final PdfObject parent;

	/**
	 * Creates an empty dictionary
	 *
	 * @param document {@link PDDocument}
	 */
	public PdfBoxDict(final PDDocument document) {
		this(new COSDictionary(), document);
	}

	/**
	 * Default constructor
	 *
	 * @param wrapped {@link COSDictionary}
	 * @param document {@link PDDocument}
	 */
	public PdfBoxDict(final COSDictionary wrapped, final PDDocument document) {
		this(wrapped, document, null);
	}

	/**
	 * Constructor with a parent object
	 *
	 * @param wrapped {@link COSDictionary}
	 * @param document {@link PDDocument}
	 */
	public PdfBoxDict(final COSDictionary wrapped, final PDDocument document, final PdfObject parent) {
		Objects.requireNonNull(wrapped, "Pdf dictionary shall be provided!");
		Objects.requireNonNull(document, "Pdf document shall be provided!");
		this.wrapped = wrapped;
		this.document = document;
		this.parent = parent;
	}

	@Override
	public COSDictionary getValue() {
		return wrapped;
	}

	@Override
	public PdfObject getParent() {
		return parent;
	}

	@Override
	public PdfDict getAsDict(String name) {
		COSBase cosBaseObject = wrapped.getDictionaryObject(name);
		if (cosBaseObject == null) {
			return null;
		}
		COSDictionary cosDictionary;
		if (cosBaseObject instanceof COSDictionary) {
			cosDictionary = (COSDictionary) cosBaseObject;
		} else if (cosBaseObject instanceof COSObject) {
			COSObject cosObject = (COSObject) cosBaseObject;
			cosDictionary = (COSDictionary) cosObject.getObject();
		} else {
			LOG.warn("Unable to extract entry with name '{}' as dictionary!", name);
			return null;
		}
		return new PdfBoxDict(cosDictionary, document, this);
	}

	@Override
	public PdfArray getAsArray(String name) {
		COSBase val = wrapped.getDictionaryObject(name);
		if (val instanceof COSArray) {
			return new PdfBoxArray((COSArray) val, document, this);
		}
		return null;
	}

	@Override
	public byte[] getBinariesValue(String name) throws IOException {
		COSBase val = wrapped.getDictionaryObject(name);
		if (val instanceof COSString) {
			return ((COSString) val).getBytes();
		}
		throw new IOException(name + " was expected to be a COSString element but was : " + val);
	}

	@Override
	public String[] list() {
		final Set<COSName> cosNames = wrapped.keySet();
		List<String> result = new ArrayList<>(cosNames.size());
		for (final COSName cosName : cosNames) {
			final String name = cosName.getName();
			result.add(name);
		}
		return result.toArray(new String[result.size()]);
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

	@Override
	public Number getNumberValue(String name) {
		COSBase val = wrapped.getDictionaryObject(name);
		if (val != null) {
			if (val instanceof COSFloat) {
				return ((COSFloat) val).floatValue();
			} else if (val instanceof COSNumber) {
				return ((COSNumber) val).longValue();
			}
		}
		return null;
	}

	@Override
	public PdfObject getObject(String name) {
		COSBase dictionaryObject = wrapped.getDictionaryObject(name);
		if (dictionaryObject == null) {
			return null;
		} else if (dictionaryObject instanceof COSDictionary ||
				dictionaryObject instanceof COSObject) {
			return getAsDict(name);
		} else if (dictionaryObject instanceof COSArray) {
			return getAsArray(name);
		} else if (dictionaryObject instanceof COSString) {
			return new PdfSimpleObject(getStringValue(name), this);
		} else if (dictionaryObject instanceof COSName) {
			return new PdfSimpleObject(getNameValue(name), this);
		} else if (dictionaryObject instanceof COSNumber) {
			return new PdfSimpleObject(getNumberValue(name), this);
		} else if (dictionaryObject instanceof COSBoolean) {
			return new PdfSimpleObject(((COSBoolean) dictionaryObject).getValueAsObject(), this);
		} else if (dictionaryObject instanceof COSNull) {
			return null;
		} else {
			LOG.warn("Unable to process an entry with name '{}' of type '{}'.", name, dictionaryObject.getClass());
		}
		return null;
	}

	@Override
	@Deprecated
	public Long getObjectNumber(String name) {
		PdfObjectKey objectKey = getObjectKey(name);
		if (objectKey != null) {
			return objectKey.getNumber();
		}
		return null;
	}

	@Override
	public PdfBoxObjectKey getObjectKey(String name) {
		COSBase dictionaryObject = wrapped.getItem(name);
		if (dictionaryObject instanceof COSObject) {
			return new PdfBoxObjectKey(dictionaryObject.getKey());
		}
		return null;
	}

	@Override
	public byte[] getStreamBytes() throws IOException {
		if (wrapped instanceof COSStream) {
			try (InputStream is = ((COSStream) wrapped).createInputStream()) {
				return Utils.toByteArray(is);
			}
		}
		return null;
	}

	@Override
	public InputStream createRawInputStream() throws IOException {
		if (wrapped instanceof COSStream) {
			return ((COSStream) wrapped).createRawInputStream();
		}
		return null;
	}

	@Override
	public long getRawStreamSize() throws IOException {
		try (InputStream is = createRawInputStream()) {
			if (is != null) {
				return Utils.getInputStreamSize(is);
			}
		}
		return -1;
	}

	@Override
	public void setPdfObjectValue(String key, PdfObject pdfObject) {
		Object value = pdfObject.getValue();
		if (!(value instanceof COSBase)) {
			throw new UnsupportedOperationException("pdfObject argument shall be of COSBase type!");
		}
		wrapped.setItem(key, (COSBase) value);
	}

	@Override
	public void setNameValue(String key, String value) {
		wrapped.setName(key, value);
	}

	@Override
	public void setStringValue(String key, String value) {
		wrapped.setString(key, value);
	}

	@Override
	public void setIntegerValue(String key, Integer value) {
		wrapped.setInt(key, value);
	}

	@Override
	public void setDirect(boolean direct) {
		wrapped.setDirect(direct);
	}

	@Override
	public boolean match(PdfDict pdfDict) {
		if (!(pdfDict instanceof PdfBoxDict)) {
			throw new UnsupportedOperationException("pdfDict argument shall be of PdfBoxDict type!");
		}
		PdfBoxDict pdfBoxDict = (PdfBoxDict) pdfDict;
		for (COSName key : pdfBoxDict.wrapped.keySet()) {
			COSBase targetObject = pdfBoxDict.wrapped.getDictionaryObject(key);
			COSBase currentObject = wrapped.getDictionaryObject(key);
			if (targetObject != null && !targetObject.equals(currentObject)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public String toString() {
		return wrapped.toString();
	}

}
