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
package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESWithOcspFromDssRevisionTest extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/Signature-P-DE_SCI-4.pdf"));
	}
	
	@Override
	protected void checkValidationContext(SignedDocumentValidator validator) {
		super.checkValidationContext(validator);

		assertTrue(validator instanceof PDFDocumentValidator);
		PDFDocumentValidator pdfDocumentValidator = (PDFDocumentValidator) validator;

		assertEquals(1, pdfDocumentValidator.getSignatures().size());
		assertEquals(2, pdfDocumentValidator.getDssDictionaries().size());

		for (PdfDssDict pdfDssDict : pdfDocumentValidator.getDssDictionaries()) {
			assertEquals(0, pdfDssDict.getCRLs().size());
			assertEquals(3, pdfDssDict.getOCSPs().size());
		}
	}

	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);

		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());

		boolean sigTstFound = false;
		boolean arcTstFound = false;
		for (TimestampWrapper timestampWrapper : timestampList) {
			if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
				sigTstFound = true;
			} else if (TimestampType.DOCUMENT_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertEquals(ArchiveTimestampType.PAdES, timestampWrapper.getArchiveTimestampType());
				assertEquals(1, timestampWrapper.getTimestampedSignatures().size());
				assertEquals(1, timestampWrapper.getTimestampedTimestamps().size());
				assertEquals(11, timestampWrapper.getTimestampedCertificates().size()); // includes certificates from OCSP tokens
				assertEquals(6, timestampWrapper.getTimestampedRevocations().size());
				arcTstFound = true;
			}
		}
		assertTrue(sigTstFound);
		assertTrue(arcTstFound);
	}
}
