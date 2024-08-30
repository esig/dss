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
package eu.europa.esig.dss.asic.cades.validation;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.test.validation.AbstractTestDocumentValidator;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCWithCAdESValidatorTest extends AbstractTestDocumentValidator {

	@Test
	void isSupported() {
		ASiCContainerWithCAdESValidator validator = new ASiCContainerWithCAdESValidator();

		byte[] wrongBytes = new byte[] { 1, 2 };
		assertFalse(validator.isSupported(new InMemoryDocument(wrongBytes)));
		assertFalse(validator.isSupported(new InMemoryDocument(wrongBytes, "test", MimeTypeEnum.PDF)));
		assertFalse(validator.isSupported(new InMemoryDocument(wrongBytes, "test")));
		assertFalse(validator.isSupported(new InMemoryDocument(wrongBytes, "test", MimeTypeEnum.XML)));
		assertFalse(validator.isSupported(new InMemoryDocument(wrongBytes, "test.p7c")));

		assertTrue(validator.isSupported(new FileDocument("src/test/resources/validation/onefile-ok.asice")));
		assertTrue(validator.isSupported(new FileDocument("src/test/resources/validation/onefile-ok.asics")));
		assertTrue(validator.isSupported(new FileDocument("src/test/resources/validation/multifiles-ok.asice")));
		assertTrue(validator.isSupported(new FileDocument("src/test/resources/validation/multifiles-ok.asics")));
		assertTrue(validator.isSupported(new FileDocument("src/test/resources/validation/evidencerecord/cades-lt-with-er.sce")));
		assertTrue(validator.isSupported(new FileDocument("src/test/resources/validation/evidencerecord/er-one-file.asics")));
		assertTrue(validator.isSupported(new FileDocument("src/test/resources/validation/evidencerecord/er-multi-files.asice")));
		assertTrue(validator.isSupported(new FileDocument("src/test/resources/signable/asic_cades.zip")));
		assertTrue(validator.isSupported(new FileDocument("src/test/resources/signable/test.zip")));
		assertTrue(validator.isSupported(new FileDocument("src/test/resources/signable/empty.zip")));

		assertFalse(validator.isSupported(new FileDocument("src/test/resources/signature-policy.der")));
		assertFalse(validator.isSupported(new FileDocument("src/test/resources/signable/test.txt")));
		assertFalse(validator.isSupported(new FileDocument("src/test/resources/signable/asic_xades.zip")));
		assertFalse(validator.isSupported(new FileDocument("src/test/resources/signable/document.odt")));
		assertFalse(validator.isSupported(new FileDocument("src/test/resources/signable/asic_xades_er.sce")));
		assertFalse(validator.isSupported(new FileDocument("src/test/resources/signable/asic_xades_er.scs")));
	}

	@Override
	protected SignedDocumentValidator initEmptyValidator() {
		return new ASiCContainerWithCAdESValidator();
	}

	@Override
	protected SignedDocumentValidator initValidator(DSSDocument document) {
		return new ASiCContainerWithCAdESValidator(document);
	}

	@Override
	protected List<DSSDocument> getValidDocuments() {
		List<DSSDocument> documents = new ArrayList<>();
		documents.add(new FileDocument("src/test/resources/validation/onefile-ok.asice"));
		documents.add(new FileDocument("src/test/resources/validation/onefile-ok.asics"));
		documents.add(new FileDocument("src/test/resources/validation/multifiles-ok.asice"));
		documents.add(new FileDocument("src/test/resources/validation/multifiles-ok.asics"));
		documents.add(new FileDocument("src/test/resources/validation/evidencerecord/cades-lt-with-er.sce"));
		documents.add(new FileDocument("src/test/resources/signable/asic_cades.zip"));
		return documents;
	}

	@Override
	protected DSSDocument getMalformedDocument() {
		return new FileDocument("src/test/resources/validation/malformed-container.asics");
	}

	@Override
	protected DSSDocument getOtherTypeDocument() {
		return new FileDocument("src/test/resources/signable/test.txt");
	}

	@Override
	protected DSSDocument getNoSignatureDocument() {
		// not applicable
		return null;
	}

	@Override
	protected DSSDocument getXmlEvidenceRecordDocument() {
		// not applicable
		return null;
	}

	@Test
	void validateEmptyContainer() {
		DSSDocument document = new FileDocument("src/test/resources/signable/empty.zip");
		DocumentValidator validator = initValidator(document);
		validate(validator, false);
	}

	@Test
	void validateZipContainer() {
		DSSDocument document = new FileDocument("src/test/resources/signable/test.zip");
		DocumentValidator validator = initValidator(document);
		validate(validator, false);
	}

	@Test
	void validateEvidenceRecordContainer() {
		DSSDocument document = new FileDocument("src/test/resources/validation/evidencerecord/er-multi-files.asice");
		DocumentValidator validator = initValidator(document);
		validate(validator, false);
	}

}
