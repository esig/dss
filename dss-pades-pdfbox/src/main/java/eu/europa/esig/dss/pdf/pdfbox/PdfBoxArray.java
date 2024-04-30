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

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pdf.PdfArray;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfObject;
import eu.europa.esig.dss.pdf.PdfSimpleObject;
import eu.europa.esig.dss.spi.DSSUtils;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSBoolean;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSInteger;
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
import java.util.Objects;

/**
 * The PDFBox implementation of {@code eu.europa.esig.dss.pdf.PdfArray}
 */
class PdfBoxArray implements PdfArray {

	private static final Logger LOG = LoggerFactory.getLogger(PdfBoxArray.class);

	/** The PDFBox object */
	private final COSArray wrapped;

	/**
	 * The document
	 *
	 * NOTE for developers: Retain this reference ! PDDocument must not be garbage collected
	 */
	private final PDDocument document;

	/** Parent object */
	private final PdfObject parent;

	/**
	 * Constructor to create a new empty array
	 *
	 * @param document {@link PDDocument}
	 */
	public PdfBoxArray(final PDDocument document) {
		this(new COSArray(), document);
	}


	/**
	 * Default constructor
	 *
	 * @param wrapped {@link COSArray}
	 * @param document {@link PDDocument}
	 */
	public PdfBoxArray(final COSArray wrapped, final PDDocument document) {
		this(wrapped, document, null);
	}

	/**
	 * Default constructor
	 *
	 * @param wrapped {@link COSArray}
	 * @param document {@link PDDocument}
	 */
	public PdfBoxArray(final COSArray wrapped, final PDDocument document, final PdfObject parent) {
		Objects.requireNonNull(wrapped, "Pdf array shall be provided!");
		Objects.requireNonNull(document, "Pdf document shall be provided!");
		this.wrapped = wrapped;
		this.document = document;
		this.parent = parent;
	}

	@Override
	public COSArray getValue() {
		return wrapped;
	}

	@Override
	public PdfObject getParent() {
		return parent;
	}

	@Override
	public int size() {
		return wrapped.size();
	}

	@Override
	public byte[] getStreamBytes(int i) throws IOException {
		COSBase val = wrapped.get(i);
		return toBytes(val);
	}

	private byte[] toBytes(COSBase val) throws IOException {
		COSStream cosStream = null;
		if (val instanceof COSObject) {
			COSObject o = (COSObject) val;
			final COSBase object = o.getObject();
			if (object instanceof COSStream) {
				cosStream = (COSStream) object;
			}
		}
		if (cosStream == null) {
			throw new DSSException("Cannot find value for " + val + " of class " + val.getClass());
		}
		try (InputStream is = cosStream.createInputStream()) {
			return DSSUtils.toByteArray(is);
		}
	}

	@Override
	public Long getObjectNumber(int i) {
		COSBase val = wrapped.get(i);
		if (val instanceof COSObject) {
			return ((COSObject) val).getObjectNumber();
		}
		return null;
	}

	@Override
	public Number getNumber(int i) {
		COSBase val = wrapped.get(i);
		if (val != null) {
			if (val instanceof COSInteger) {
				return ((COSInteger) val).longValue();
			} else if (val instanceof COSNumber) {
				return ((COSNumber) val).floatValue();
			}
		}
		return null;
	}

	@Override
	public String getString(int i) {
		return wrapped.getString(i);
	}

	@Override
	public PdfDict getAsDict(int i) {
		COSDictionary cosDictionary = null;
		COSBase cosBaseObject = wrapped.get(i);
		if (cosBaseObject instanceof COSDictionary) {
			cosDictionary = (COSDictionary) cosBaseObject;
		} else if (cosBaseObject instanceof COSObject) {
			COSObject cosObject = (COSObject) cosBaseObject;
			cosDictionary = (COSDictionary) cosObject.getObject();
		}
		if (cosDictionary != null) {
			return new PdfBoxDict(cosDictionary, document, this);
		}
		LOG.warn("Unable to extract array entry as dictionary!");
		return null;
	}

	@Override
	public PdfObject getObject(int i) {
		COSBase dictionaryObject = wrapped.getObject(i);
		if (dictionaryObject == null) {
			return null;
		}
		if (dictionaryObject instanceof COSDictionary ||
				dictionaryObject instanceof COSObject) {
			return getAsDict(i);
		} else if (dictionaryObject instanceof COSArray) {
			return new PdfBoxArray((COSArray) dictionaryObject, document, this);
		} else if (dictionaryObject instanceof COSString) {
			return new PdfSimpleObject(getString(i), this);
		} else if (dictionaryObject instanceof COSName) {
			return new PdfSimpleObject(wrapped.getName(i), this);
		} else if (dictionaryObject instanceof COSNumber) {
			return new PdfSimpleObject(getNumber(i), this);
		}else if (dictionaryObject instanceof COSBoolean) {
			return new PdfSimpleObject(((COSBoolean) dictionaryObject).getValueAsObject(), this);
		} else if (dictionaryObject instanceof COSNull) {
			return null;
		} else {
			LOG.warn("Unable to process an entry on position '{}' of type '{}'.", i, dictionaryObject.getClass());
		}
		return null;
	}

	@Override
	public void addObject(PdfObject pdfObject) {
		Object value = pdfObject.getValue();
		if (!(value instanceof COSBase)) {
			throw new UnsupportedOperationException("The object to be added shall be of type COSBase!");
		}
		wrapped.add((COSBase) value);
	}

	@Override
	public void setDirect(boolean direct) {
		wrapped.setDirect(direct);
	}

	@Override
	public String toString() {
		return wrapped.toString();
	}

}
