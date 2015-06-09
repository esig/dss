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
import java.io.InputStream;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.pdf.PdfReader;

class PdfBoxReader implements PdfReader {

	private static final Logger logger = LoggerFactory.getLogger(PdfBoxReader.class);

	private PDDocument wrapped;

	public PdfBoxReader(InputStream inputstream) throws IOException {
		wrapped = PDDocument.load(inputstream);
	}

	@Override
	public PdfBoxDict getCatalog() {
		return new PdfBoxDict(wrapped.getDocumentCatalog().getCOSDictionary(), wrapped);
	}

	@Override
	public void finalize() throws Throwable {
		if (wrapped != null) {
			try {
				wrapped.close();
			} catch (IOException e) {
				logger.error("Error while closing PDDocument", e);
			}
		}
		wrapped = null;
		super.finalize();
	}

	PDDocument getPDDocument() {
		return wrapped;
	}

}