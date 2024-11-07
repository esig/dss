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
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfMemoryUsageSetting;
import eu.europa.esig.dss.test.PKIFactoryAccess;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Calendar;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PdfBoxDocumentReaderTest extends PKIFactoryAccess {

	private static final String FILE = "/validation/doc-firmado-LT.pdf";

	@Test
	void testPdfBoxUtils() throws Exception {
		try (PdfDocumentReader documentReader = new PdfBoxDocumentReader(new InMemoryDocument(getClass().getResourceAsStream(FILE)))) {
			PdfDssDict dssDictionary = documentReader.getDSSDictionary();
			assertNotNull(dssDictionary);
		}
	}
	
	@Test
	void testPdfBoxUtilsEmptyDocument() throws Exception {
		assertThrows(IOException.class, () -> new PdfBoxDocumentReader(InMemoryDocument.createEmptyDocument()));
	}
	
	@Test
	void testPdfBoxUtilsNull() throws Exception {
		Exception exception = assertThrows(NullPointerException.class, () -> new PdfBoxDocumentReader((DSSDocument)null));
		assertEquals("The document must be defined!", exception.getMessage());
		exception = assertThrows(NullPointerException.class, () -> new PdfBoxDocumentReader((byte[])null, null));
		assertEquals("The document binaries must be defined!", exception.getMessage());
	}

	@Test
	void permissionsReadOnlyDocument() throws IOException {
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
	void permissionsProtectedDocument() throws IOException {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/protected/open_protected.pdf"));
		try (PdfBoxDocumentReader documentReader = new PdfBoxDocumentReader(dssDocument, " ")) {
			assertTrue(documentReader.isEncrypted());
			assertTrue(documentReader.isOpenWithOwnerAccess());
			assertTrue(documentReader.canFillSignatureForm());
			assertTrue(documentReader.canCreateSignatureField());
		}
	}

	@Test
	void permissionsEditionProtectedDocument() throws IOException {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/protected/edition_protected_none.pdf"));
		try (PdfBoxDocumentReader documentReader = new PdfBoxDocumentReader(dssDocument, " ")) {
			assertTrue(documentReader.isEncrypted());
			assertTrue(documentReader.isOpenWithOwnerAccess());
			assertTrue(documentReader.canFillSignatureForm());
			assertTrue(documentReader.canCreateSignatureField());
		}
	}

	@Test
	void permissionsEditionNoFieldsProtectedDocument() throws IOException {
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
	void permissionsEditionSixProtectedDocument() throws IOException {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/protected/restricted_fields.pdf"));
		try (PdfBoxDocumentReader documentReader = new PdfBoxDocumentReader(dssDocument)) {
			assertTrue(documentReader.isEncrypted());
			assertFalse(documentReader.isOpenWithOwnerAccess());
			assertTrue(documentReader.canFillSignatureForm());
			assertFalse(documentReader.canCreateSignatureField());
		}
	}

	@Test
	void generateDocumentIdTest() throws IOException {
		DSSDocument firstDocument = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
		DSSDocument secondDocument = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));

		Date date = new Date();
		PAdESSignatureParameters parametersOne = new PAdESSignatureParameters();
		parametersOne.bLevel().setSigningDate(date);
		PAdESSignatureParameters parametersTwo = new PAdESSignatureParameters();
		parametersTwo.bLevel().setSigningDate(date);

		try (PdfBoxDocumentReader firstReader = new PdfBoxDocumentReader(firstDocument);
			 PdfBoxDocumentReader secondReader = new PdfBoxDocumentReader(secondDocument)) {
			assertEquals(firstReader.generateDocumentId(parametersOne), firstReader.generateDocumentId(parametersOne));
			assertEquals(firstReader.generateDocumentId(parametersTwo), firstReader.generateDocumentId(parametersTwo));
			assertEquals(secondReader.generateDocumentId(parametersOne), secondReader.generateDocumentId(parametersOne));
			assertEquals(secondReader.generateDocumentId(parametersTwo), secondReader.generateDocumentId(parametersTwo));

			assertEquals(firstReader.generateDocumentId(parametersOne), firstReader.generateDocumentId(parametersTwo));
			assertEquals(secondReader.generateDocumentId(parametersOne), secondReader.generateDocumentId(parametersTwo));

			assertNotEquals(firstReader.generateDocumentId(parametersOne), secondReader.generateDocumentId(parametersOne));
			assertNotEquals(firstReader.generateDocumentId(parametersTwo), secondReader.generateDocumentId(parametersTwo));

			long docIdOne = firstReader.generateDocumentId(parametersOne);
			firstDocument.setName("newDocName");
			assertNotEquals(docIdOne, firstReader.generateDocumentId(parametersOne));

			secondDocument.setName("newDocName");
			assertNotEquals(firstReader.generateDocumentId(parametersOne), secondReader.generateDocumentId(parametersOne));

			parametersTwo.setSigningCertificate(getCertificate(GOOD_USER));
			parametersTwo.reinit();
			assertEquals(firstReader.generateDocumentId(parametersTwo), firstReader.generateDocumentId(parametersTwo));
			assertNotEquals(firstReader.generateDocumentId(parametersOne), firstReader.generateDocumentId(parametersTwo));

			parametersOne.setSigningCertificate(getCertificate(RSA_SHA3_USER));
			parametersOne.reinit();
			assertEquals(firstReader.generateDocumentId(parametersOne), firstReader.generateDocumentId(parametersOne));
			assertNotEquals(firstReader.generateDocumentId(parametersOne), firstReader.generateDocumentId(parametersTwo));

			// time test
			for (int i = 0; i < 1000; i++) {
				PAdESSignatureParameters sameTimeParameters = new PAdESSignatureParameters();
				sameTimeParameters.bLevel().setSigningDate(date);

				PAdESSignatureParameters diffTimeParameters = new PAdESSignatureParameters();
				Calendar calendar = Calendar.getInstance();
				calendar.setTime(new Date());
				calendar.add(Calendar.MILLISECOND, 1);
				diffTimeParameters.bLevel().setSigningDate(calendar.getTime());
				assertNotEquals(firstReader.generateDocumentId(sameTimeParameters),
						firstReader.generateDocumentId(diffTimeParameters));
				assertEquals(firstReader.generateDocumentId(diffTimeParameters),
						firstReader.generateDocumentId(diffTimeParameters));
			}
		}
	}

	@Test
	void fileHeaderVersionTest() throws IOException {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
		assertEquals(1.4f, new PdfBoxDocumentReader(dssDocument).getPdfHeaderVersion());
		dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/testdoc.pdf"));
		assertEquals(1.7f, new PdfBoxDocumentReader(dssDocument).getPdfHeaderVersion());
		dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/pdf-2.0.pdf"));
		assertEquals(2.0f, new PdfBoxDocumentReader(dssDocument).getPdfHeaderVersion());
		dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/muestra-firmado-firmado.pdf"));
		assertEquals(1.4f, new PdfBoxDocumentReader(dssDocument).getPdfHeaderVersion());
	}

	@Test
	void versionTest() throws IOException {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
		assertEquals(1.4f, new PdfBoxDocumentReader(dssDocument).getVersion());
		dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/testdoc.pdf"));
		assertEquals(1.7f, new PdfBoxDocumentReader(dssDocument).getVersion());
		dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/pdf-2.0.pdf"));
		assertEquals(2.0f, new PdfBoxDocumentReader(dssDocument).getVersion());
		dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/muestra-firmado-firmado.pdf"));
		assertEquals(2.0f, new PdfBoxDocumentReader(dssDocument).getVersion());
	}

	@Test
	void setVersionTest() throws IOException {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

		PdfBoxDocumentReader documentReader = new PdfBoxDocumentReader(dssDocument);
		assertEquals(1.4f, documentReader.getVersion());

		documentReader.setVersion(1.7f);
		assertEquals(1.7f, documentReader.getVersion());

		documentReader.setVersion(2.0f);
		assertEquals(2.0f, documentReader.getVersion());
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
