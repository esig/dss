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
package eu.europa.esig.dss.asic.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class ZipBombingTest {

	@Test
	public void zipBombing() {
		FileDocument doc = new FileDocument("src/test/resources/validation/zip-bomb.asice");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
	}

	@Test
	public void zipBombingPackageZip() {
		FileDocument doc = new FileDocument("src/test/resources/validation/zip-bomb-package-zip.asics");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
	}

	@Test
	public void zipBombingOneLevelAsice() {
		FileDocument doc = new FileDocument("src/test/resources/validation/one-level-zip-bombing.asice");
		Exception exception = assertThrows(DSSException.class, () -> SignedDocumentValidator.fromDocument(doc));
		assertEquals("Document format not recognized/handled", exception.getMessage());
	}

	@Test
	public void zipBombingOneLevelAsice2() {
		FileDocument doc = new FileDocument("src/test/resources/validation/one-level-zip-bombing.asice");
		Exception exception = assertThrows(DSSException.class, () -> new ASiCContainerWithXAdESValidator(doc));
		assertEquals("Unable to close entry", exception.getMessage());
	}

	@Test
	public void zipBombingOneLevelAsics() {
		FileDocument doc = new FileDocument("src/test/resources/validation/zip-bomb-package-zip-1gb.asics");
		Exception exception = assertThrows(DSSException.class, () -> SignedDocumentValidator.fromDocument(doc));
		assertEquals("Document format not recognized/handled", exception.getMessage());
	}

	@Test
	public void zipBombingOneLevelAsics2() {
		FileDocument doc = new FileDocument("src/test/resources/validation/zip-bomb-package-zip-1gb.asics");
		Exception exception = assertThrows(DSSException.class, () -> new ASiCContainerWithXAdESValidator(doc));
		assertEquals("Zip Bomb detected in the ZIP container. Validation is interrupted.", exception.getMessage());
	}

	@Test
	public void zipBombingTooManyFilesAsice() {
		FileDocument doc = new FileDocument("src/test/resources/validation/container-too-many-files.asice");
		Exception exception = assertThrows(DSSException.class, () -> SignedDocumentValidator.fromDocument(doc));
		assertEquals("Document format not recognized/handled", exception.getMessage());
	}

	@Test
	public void zipBombingTooManyFilesAsics() {
		FileDocument doc = new FileDocument("src/test/resources/validation/container-too-many-files.asics");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
	}

}
