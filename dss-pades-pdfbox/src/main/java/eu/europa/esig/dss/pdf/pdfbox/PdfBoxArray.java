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

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.PDDocument;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.pdf.PdfArray;

class PdfBoxArray implements PdfArray {

	private COSArray wrapped;

	// Retain this reference ! PDDocument must not be garbage collected
	@SuppressWarnings("unused")
	private PDDocument document;

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
	public long getObjectNumber(int i) {
		COSObject cosObject = (COSObject) wrapped.get(i);
		return cosObject.getObjectNumber();
	}

	@Override
	public int getInt(int i) throws IOException {
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
			throw new RuntimeException("Cannot find value for " + val + " of class " + val.getClass());
		}
		return DSSUtils.toByteArray(cosStream.createInputStream());
	}

	@Override
	public String toString() {
		return wrapped.toString();
	}

}
