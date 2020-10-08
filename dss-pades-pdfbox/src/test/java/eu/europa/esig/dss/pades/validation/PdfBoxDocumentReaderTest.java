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
package eu.europa.esig.dss.pades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDocumentReader;
import eu.europa.esig.dss.spi.DSSUtils;

public class PdfBoxDocumentReaderTest {

	private static final String FILE = "/validation/doc-firmado-LT.pdf";

	@Test
	public void testPdfBoxUtils() throws Exception {
		try (PdfDocumentReader documentReader = new PdfBoxDocumentReader(new InMemoryDocument(getClass().getResourceAsStream(FILE)))) {
			PdfDssDict dssDictionary = documentReader.getDSSDictionary();
			assertNotNull(dssDictionary);
		}
	}
	
	@Test
	public void testPdfBoxUtilsEmptyDocument() throws Exception {
		assertThrows(IOException.class, () ->  {
			new PdfBoxDocumentReader(new InMemoryDocument(DSSUtils.EMPTY_BYTE_ARRAY, "empty_doc"));
		});
	}
	
	@Test
	public void testPdfBoxUtilsNull() throws Exception {
		Exception exception = assertThrows(NullPointerException.class, () ->  {
			new PdfBoxDocumentReader((DSSDocument)null);
		});
		assertEquals("The document must be defined!", exception.getMessage());
		exception = assertThrows(NullPointerException.class, () ->  {
			new PdfBoxDocumentReader((byte[])null, null);
		});
		assertEquals("The document binaries must be defined!", exception.getMessage());
	}
}
