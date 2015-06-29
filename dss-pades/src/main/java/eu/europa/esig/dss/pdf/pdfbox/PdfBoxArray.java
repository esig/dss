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
import eu.europa.esig.dss.pdf.PdfStream;
import eu.europa.esig.dss.pdf.model.ModelPdfArray;
import eu.europa.esig.dss.pdf.model.ModelPdfStream;

class PdfBoxArray implements PdfArray {

	COSArray wrapped;

	// Retain this reference ! PDDocument must not be garbage collected
	@SuppressWarnings("unused")
	private PDDocument document;

	public PdfBoxArray() {
		wrapped = new COSArray();
	}

	public PdfBoxArray(COSArray wrapped, PDDocument document) {
		this.wrapped = wrapped;
		this.document = document;
	}

	public PdfBoxArray(ModelPdfArray array) {
		this();
		for(Object o : array.getValues()) {
			if(o instanceof ModelPdfStream) {
				add(new PdfBoxStream((ModelPdfStream) o));
			} else {
				throw new IllegalArgumentException(o.getClass().getName());
			}
		}
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

	private byte[] toBytes(COSBase val) throws IOException {
		COSStream cosStream = null;
		if(val instanceof COSObject) {
			COSObject o = (COSObject) val;
			final COSBase object = o.getObject();
			if(object instanceof COSStream) {
				cosStream = (COSStream) object;
			}
		}
		if(cosStream == null) {
			throw new RuntimeException("Cannot find value for " + val + " of class " + val.getClass());
		}
		final byte[] bytes = DSSUtils.toByteArray(cosStream.getUnfilteredStream());
		return bytes;
	}

	@Override
	public String toString() {
		return wrapped.toString();
	}

	@Override
	public void add(PdfStream stream) {
		PdfBoxStream s = (PdfBoxStream) stream;
		wrapped.add(s.wrapped);
		wrapped.setNeedToBeUpdate(true);
	}
}