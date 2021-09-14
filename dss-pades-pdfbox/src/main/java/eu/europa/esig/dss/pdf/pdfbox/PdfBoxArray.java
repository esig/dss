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
import eu.europa.esig.dss.spi.DSSUtils;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSBoolean;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSFloat;
import org.apache.pdfbox.cos.COSInteger;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSNull;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * The PDFBox implementation of {@code eu.europa.esig.dss.pdf.PdfArray}
 */
class PdfBoxArray implements PdfArray {

	private static final Logger LOG = LoggerFactory.getLogger(PdfBoxArray.class);

	/** The PDFBox object */
	private COSArray wrapped;

	/**
	 * The document
	 *
	 * NOTE for developers: Retain this reference ! PDDocument must not be garbage collected
	 */
	private PDDocument document;

	/**
	 * Default constructor
	 *
	 * @param wrapped {@link COSArray}
	 * @param document {@link PDDocument}
	 */
	public PdfBoxArray(COSArray wrapped, PDDocument document) {
		this.wrapped = wrapped;
		this.document = document;
	}

	@Override
	public int size() {
		return wrapped.size();
	}

	@Override
	public byte[] getBytes(int i) throws IOException {
		COSBase val = wrapped.get(i);
		return toBytes(val);
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
	public Integer getInt(int i) {
		return wrapped.getInt(i);
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
		return DSSUtils.toByteArray(cosStream.createInputStream());
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
			return new PdfBoxDict(cosDictionary, document);
		}
		LOG.warn("Unable to extract array entry as dictionary!");
		return null;
	}

	@Override
	public Object getObject(int i) {
		COSBase dictionaryObject = wrapped.getObject(i);
		if (dictionaryObject == null) {
			return null;
		}
		if (dictionaryObject instanceof COSDictionary ||
				dictionaryObject instanceof COSObject) {
			return getAsDict(i);
		} else if (dictionaryObject instanceof COSArray) {
			return new PdfBoxArray((COSArray) dictionaryObject, document);
		} else if (dictionaryObject instanceof COSString) {
			return getString(i);
		} else if (dictionaryObject instanceof COSName) {
			return wrapped.getName(i);
		} else if (dictionaryObject instanceof COSInteger) {
			return getInt(i);
		}else if (dictionaryObject instanceof COSBoolean) {
			return ((COSBoolean) dictionaryObject).getValueAsObject();
		} else if (dictionaryObject instanceof COSFloat) {
			return ((COSFloat) dictionaryObject).floatValue();
		} else if (dictionaryObject instanceof COSNull) {
			return null;
		} else {
			LOG.warn("Unable to process an entry on position '{}' of type '{}'.", i, dictionaryObject.getClass());
		}
		return null;
	}

	@Override
	public String toString() {
		return wrapped.toString();
	}

}
