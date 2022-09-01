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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.spi.DSSUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
		assertThrows(IOException.class, () -> new PdfBoxDocumentReader(new InMemoryDocument(DSSUtils.EMPTY_BYTE_ARRAY, "empty_doc")));
	}
	
	@Test
	public void testPdfBoxUtilsNull() throws Exception {
		Exception exception = assertThrows(NullPointerException.class, () -> new PdfBoxDocumentReader((DSSDocument)null));
		assertEquals("The document must be defined!", exception.getMessage());
		exception = assertThrows(NullPointerException.class, () -> new PdfBoxDocumentReader((byte[])null, null));
		assertEquals("The document binaries must be defined!", exception.getMessage());
	}

	@Test
	public void permissionsReadOnlyDocument() throws IOException {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
		try (PdfBoxDocumentReader pdfBoxDocumentReader = new PdfBoxDocumentReader(dssDocument)) {
			PDDocument pdDocument = pdfBoxDocumentReader.getPDDocument();
			AccessPermission currentAccessPermission = pdDocument.getCurrentAccessPermission();
			assertFalse(currentAccessPermission.isReadOnly());

			currentAccessPermission.setReadOnly();
			assertTrue(currentAccessPermission.isReadOnly());

			assertFalse(pdfBoxDocumentReader.isEncrypted());
			assertTrue(pdfBoxDocumentReader.isOpenWithOwnerAccess());
			assertTrue(pdfBoxDocumentReader.canFillSignatureForm());
			assertTrue(pdfBoxDocumentReader.canCreateSignatureField());
		}
	}

	@Test
	public void permissionsProtectedDocument() throws IOException {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/protected/open_protected.pdf"));
		try (PdfBoxDocumentReader documentReader = new PdfBoxDocumentReader(dssDocument, " ")) {
			assertTrue(documentReader.isEncrypted());
			assertTrue(documentReader.isOpenWithOwnerAccess());
			assertTrue(documentReader.canFillSignatureForm());
			assertTrue(documentReader.canCreateSignatureField());
		}
	}

	@Test
	public void permissionsEditionProtectedDocument() throws IOException {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/protected/edition_protected_none.pdf"));
		try (PdfBoxDocumentReader documentReader = new PdfBoxDocumentReader(dssDocument, " ")) {
			assertTrue(documentReader.isEncrypted());
			assertTrue(documentReader.isOpenWithOwnerAccess());
			assertTrue(documentReader.canFillSignatureForm());
			assertTrue(documentReader.canCreateSignatureField());
		}
	}

	@Test
	public void permissionsEditionNoFieldsProtectedDocument() throws IOException {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/protected/edition_protected_signing_allowed_no_field.pdf"));
		try (PdfBoxDocumentReader documentReader = new PdfBoxDocumentReader(dssDocument, " ")) {
			assertTrue(documentReader.isEncrypted());
			assertTrue(documentReader.isOpenWithOwnerAccess());
			assertTrue(documentReader.canFillSignatureForm());
			assertTrue(documentReader.canCreateSignatureField());
		}
	}

	// NOTE : Edition 6 is not supported in OpenPdf
	@Test
	public void permissionsEditionSixProtectedDocument() throws IOException {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/protected/restricted_fields.pdf"));
		try (PdfBoxDocumentReader documentReader = new PdfBoxDocumentReader(dssDocument)) {
			assertTrue(documentReader.isEncrypted());
			assertFalse(documentReader.isOpenWithOwnerAccess());
			assertTrue(documentReader.canFillSignatureForm());
			assertFalse(documentReader.canCreateSignatureField());
		}
	}

}
