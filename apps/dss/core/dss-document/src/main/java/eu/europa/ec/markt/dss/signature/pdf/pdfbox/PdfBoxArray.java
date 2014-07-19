/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature.pdf.pdfbox;

import java.io.IOException;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.PDDocument;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.signature.pdf.PdfArray;
import eu.europa.ec.markt.dss.signature.pdf.PdfStream;

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
		COSStream data = null;
		if(val instanceof COSObject) {
			COSObject o = (COSObject) val;
			if(o.getObject() instanceof COSStream) {
				data = (COSStream) o.getObject();
			}
		}
		if(data == null) {
			throw new RuntimeException("Cannot find value for " + val + " of class " + val.getClass());
		}
		return DSSUtils.toByteArray(data.getFilteredStream());
	}

	@Override
	public String toString() {
		return wrapped.toString();
	}

    @Override
    public void add(PdfStream stream) throws IOException {
        PdfBoxStream s = (PdfBoxStream) stream;
        wrapped.add(s.wrapped);
        wrapped.setNeedToBeUpdate(true);
    }


}
