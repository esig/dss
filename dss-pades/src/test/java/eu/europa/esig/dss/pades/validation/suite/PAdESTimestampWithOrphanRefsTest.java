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
package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pades.validation.timestamp.PdfTimestampToken;
import eu.europa.esig.dss.pdf.PdfDocTimestampRevision;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.junit.jupiter.api.BeforeEach;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class PAdESTimestampWithOrphanRefsTest extends AbstractPAdESTestValidation {

	private static DSSDocument document;

	@BeforeEach
	public void init() {
		document = new InMemoryDocument(PAdESTimestampWithOrphanRefsTest.class
				.getResourceAsStream("/validation/dss-1959/pades-tst-with-orphan-refs.pdf"));
	}

	@Override
	protected DSSDocument getSignedDocument() {
		return document;
	}

	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);

		assertEquals(2, signatures.size());

		boolean firstSignature = false;
		boolean secondSignature = false;
		for (AdvancedSignature signature : signatures) {
			List<TimestampToken> documentTimestamps = signature.getDocumentTimestamps();
			if (documentTimestamps.size() == 2) {
				firstSignature = true;
			} else if (documentTimestamps.size() == 1) {
				secondSignature = true;
			}

			for (TimestampToken timestampToken : documentTimestamps) {
				try {
					assertTrue(timestampToken instanceof PdfTimestampToken);
					PdfTimestampToken pdfTimestampToken = (PdfTimestampToken) timestampToken;

					PdfDocTimestampRevision pdfRevision = pdfTimestampToken.getPdfRevision();
					byte[] revisionContent = PAdESUtils.getRevisionContent(document, pdfRevision.getByteRange());
					byte[] signedContent = PAdESUtils.getSignedContentFromRevision(revisionContent, pdfRevision.getByteRange());

					SignedDocumentValidator timestampValidator = SignedDocumentValidator
							.fromDocument(new InMemoryDocument(pdfTimestampToken.getEncoded()));
					timestampValidator.setCertificateVerifier(new CommonCertificateVerifier());
					timestampValidator.setDetachedContents(Arrays.asList(new InMemoryDocument(signedContent)));

					Reports reports = timestampValidator.validateDocument();
					assertNotNull(reports);

					DiagnosticData diagnosticData = reports.getDiagnosticData();
					List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
					assertEquals(1, timestampList.size());

					TimestampWrapper timestampWrapper = timestampList.get(0);
					assertTrue(timestampWrapper.isMessageImprintDataFound());
					assertTrue(timestampWrapper.isMessageImprintDataIntact());

					SimpleReport simpleReport = reports.getSimpleReport();
					assertNotEquals(Indication.FAILED, simpleReport.getIndication(pdfTimestampToken.getDSSIdAsString()));

				} catch (IOException e) {
					fail(e);
				}
			}
		}
		assertTrue(firstSignature);
		assertTrue(secondSignature);
	}

	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);

		int signatureTimestamps = 0;
		int docTimestamps = 0;
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		for (TimestampWrapper timestampWrapper : timestampList) {
			if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
				++signatureTimestamps;
			} else if (TimestampType.DOCUMENT_TIMESTAMP.equals(timestampWrapper.getType())) {
				++docTimestamps;
			}
		}
		assertEquals(2, signatureTimestamps);
		assertEquals(2, docTimestamps);
	}

	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		super.verifySimpleReport(simpleReport);

		for (String signatureId : simpleReport.getSignatureIdList()) {
			assertNotEquals(Indication.FAILED, simpleReport.getIndication(signatureId));
		}
	}

	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(2, signatures.size());

		boolean emptySigDocFound = false;
		boolean signPdfFound = false;
		for (AdvancedSignature signature : signatures) {
			List<DSSDocument> originalDocuments = validator.getOriginalDocuments(signature.getId());
			if (originalDocuments.size() == 0) {
				emptySigDocFound = true;
			} else {
				signPdfFound = true;
			}
		}
		assertTrue(emptySigDocFound);
		assertTrue(signPdfFound);
	}

}
