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

import java.io.OutputStream;

import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.io.RandomAccessBuffer;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.pdf.PdfStream;
import eu.europa.esig.dss.pdf.model.ModelPdfStream;

class PdfBoxStream implements PdfStream {

	COSStream wrapped;

	public PdfBoxStream(byte[] bytes) {
		try {
			RandomAccessBuffer storage = new RandomAccessBuffer();
			this.wrapped = new COSStream(storage);
			final OutputStream unfilteredStream = this.wrapped.createUnfilteredStream();
			unfilteredStream.write(bytes);
			unfilteredStream.flush();
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	public PdfBoxStream(ModelPdfStream stream) {
		this(stream.getBytes());
	}

}
