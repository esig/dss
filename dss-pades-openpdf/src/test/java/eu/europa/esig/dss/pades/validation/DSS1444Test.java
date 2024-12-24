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
package eu.europa.esig.dss.pades.validation;

import com.lowagie.text.exceptions.InvalidPdfException;
import com.lowagie.text.pdf.PdfReader;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS1444Test {

	@Test
	void test() throws IOException {
		try (InputStream is = getClass().getResourceAsStream("/EmptyPage-corrupted.pdf")) {
			assertThrows(InvalidPdfException.class, () -> new PdfReader(is));
		}
	}

	@Test
	void testValidation() throws IOException {
		try (InputStream is = getClass().getResourceAsStream("/EmptyPage-corrupted.pdf")) {
			PDFDocumentAnalyzer analyzer = new PDFDocumentAnalyzer(new InMemoryDocument(is, "corrupted.pdf"));
			Exception exception = assertThrows(DSSException.class, () -> analyzer.getSignatures());
			assertTrue(exception.getMessage().contains("The document with name [corrupted.pdf] is either not accessible or not PDF compatible. Reason :"));
		}
	}

	@Test
	void test2() throws IOException {
		try (InputStream is = getClass().getResourceAsStream("/EmptyPage-corrupted2.pdf")) {
			assertThrows(InvalidPdfException.class, () -> new PdfReader(is));
		}
	}

	@Test
	void test2Validation() throws IOException {
		try (InputStream is = getClass().getResourceAsStream("/EmptyPage-corrupted2.pdf")) {
			PDFDocumentAnalyzer analyzeral = new PDFDocumentAnalyzer(new InMemoryDocument(is, "corrupted.pdf"));
			Exception exception = assertThrows(DSSException.class, () -> analyzeral.getSignatures());
			assertTrue(exception.getMessage().contains("The document with name [corrupted.pdf] is either not accessible or not PDF compatible. Reason :"));
		}
	}

	@Test
	void test3() throws IOException {
		try (InputStream is = getClass().getResourceAsStream("/small-red.jpg")) {
			Exception exception = assertThrows(IOException.class, () -> new PdfReader(is));
			assertEquals("PDF header signature not found.", exception.getMessage());
		}
	}

	@Test
	void test4() throws IOException {
		try (InputStream is = getClass().getResourceAsStream("/sample.pdf")) {
			PdfReader pdfReader = new PdfReader(is);
			assertNotNull(pdfReader);
		}
	}

}
