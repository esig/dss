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
package eu.europa.esig.dss.test.validation;

import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractTestValidator {

	protected abstract SignedDocumentValidator initEmptyValidator();

	protected abstract SignedDocumentValidator initValidator(DSSDocument document);

	protected abstract List<DSSDocument> getValidDocuments();

	protected abstract DSSDocument getMalformedDocument();

	protected abstract DSSDocument getOtherTypeDocument();

	protected abstract DSSDocument getNoSignatureDocument();

	protected DSSDocument getBinaryDocument() {
		return new InMemoryDocument(new byte[] { '1', '2', '3' });
	}

	protected abstract DSSDocument getXmlEvidenceRecordDocument();

	@Test
	public void validateSignatures() {
		List<DSSDocument> documents = getValidDocuments();
		for (DSSDocument document : documents) {
			SignedDocumentValidator validator = initValidator(document);
			validate(validator, true);
		}
	}

	@Test
	public void validateFromDocument() {
		List<DSSDocument> documents = getValidDocuments();
		for (DSSDocument document : documents) {
			SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
			validate(validator, true);
		}
	}

	@Test
	public void binaryDocumentValidation() {
		DSSDocument document = getBinaryDocument();
		assertThrows(IllegalInputException.class, () -> initValidator(document));
	}

	@Test
	public void malformedDocumentValidation() {
		DSSDocument document = getMalformedDocument();
		assertThrows(IllegalInputException.class, () -> initValidator(document));
	}

	@Test
	public void otherDocumentTypeValidation() {
		DSSDocument document = getOtherTypeDocument();
		assertThrows(IllegalInputException.class, () -> initValidator(document));
	}

	@Test
	public void isSupportedValidDocument() {
		List<DSSDocument> documents = getValidDocuments();
		for (DSSDocument document : documents) {
			assertTrue(initEmptyValidator().isSupported(document));
		}
	}

	@Test
	public void isSupportedBinaryDocument() {
		assertFalse(initEmptyValidator().isSupported(getBinaryDocument()));
	}

	@Test
	public void isSupportedMalformedDocument() {
		assertFalse(initEmptyValidator().isSupported(getMalformedDocument()));
	}

	@Test
	public void isSupportedOtherTypeDocument() {
		assertFalse(initEmptyValidator().isSupported(getOtherTypeDocument()));
	}

	@Test
	public void isSupportedNoSignatureDocument() {
		DSSDocument document = getNoSignatureDocument();
		if (document != null) {
			assertTrue(initEmptyValidator().isSupported(document));
		}
	}

	@Test
	public void isSupportedEvidenceRecordDocument() {
		DSSDocument document = getXmlEvidenceRecordDocument();
		if (document != null) {
			assertFalse(initEmptyValidator().isSupported(document));
		}
	}

	@Test
	public void nullDocumentProvided() {
		assertThrows(NullPointerException.class, () ->  initValidator(null));
	}

	@Test
	public void nullFromDocument() {
		Exception exception = assertThrows(NullPointerException.class, () ->  SignedDocumentValidator.fromDocument(null));
		assertEquals("DSSDocument is null", exception.getMessage());
	}

	protected void validate(SignedDocumentValidator validator) {
		validate(validator, false);
	}

	protected void validate(SignedDocumentValidator validator, boolean containsSignature) {
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		SimpleReport simpleReport = reports.getSimpleReport();
		assertNotNull(simpleReport);
		assertEquals(containsSignature, simpleReport.getSignaturesCount() > 0);
	}

}
