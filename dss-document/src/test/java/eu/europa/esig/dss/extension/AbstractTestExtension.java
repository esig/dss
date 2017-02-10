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
package eu.europa.esig.dss.extension;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public abstract class AbstractTestExtension<SP extends AbstractSignatureParameters> {

	protected abstract DSSDocument getSignedDocument() throws Exception;

	protected abstract SignatureLevel getOriginalSignatureLevel();

	protected abstract SignatureLevel getFinalSignatureLevel();

	protected abstract DocumentSignatureService<SP> getSignatureServiceToExtend() throws Exception;

	protected SignatureValue sign(SignatureAlgorithm algo, MockPrivateKeyEntry privateKey, ToBeSigned bytesToSign) throws GeneralSecurityException {
		final Signature signature = Signature.getInstance(algo.getJCEId());
		signature.initSign(privateKey.getPrivateKey());
		signature.update(bytesToSign.getBytes());
		final byte[] signatureValue = signature.sign();
		return new SignatureValue(algo, signatureValue);
	}

	@Test
	public void test() throws Exception {
		DSSDocument signedDocument = getSignedDocument();
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		verifySimpleReport(reports.getSimpleReport());
		verifyDetailedReport(reports.getDetailedReport());

		checkOriginalLevel(diagnosticData);
		checkBLevelValid(diagnosticData);

		DSSDocument extendedDocument = extendSignature(signedDocument);

		// extendedDocument.save("target/xades.xml");

		assertNotNull(extendedDocument);
		assertNotNull(extendedDocument.getMimeType());
		assertNotNull(Utils.toByteArray(extendedDocument.openStream()));
		assertNotNull(extendedDocument.getName());

		validator = SignedDocumentValidator.fromDocument(extendedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		reports = validator.validateDocument();

		// reports.print();

		diagnosticData = reports.getDiagnosticData();
		verifySimpleReport(reports.getSimpleReport());
		verifyDetailedReport(reports.getDetailedReport());

		checkFinalLevel(diagnosticData);
		checkBLevelValid(diagnosticData);
		checkTLevelAndValid(diagnosticData);
	}

	private DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
		SP extensionParameters = getExtensionParameters();
		DocumentSignatureService<SP> service = getSignatureServiceToExtend();

		DSSDocument extendedDocument = service.extendDocument(signedDocument, extensionParameters);
		assertNotNull(extendedDocument);

		// extendedDocument.save("target/pdf.pdf");

		return extendedDocument;
	}

	protected void verifySimpleReport(SimpleReport simpleReport) {
		assertNotNull(simpleReport);

		List<String> signatureIdList = simpleReport.getSignatureIdList();
		assertTrue(Utils.isCollectionNotEmpty(signatureIdList));

		for (String sigId : signatureIdList) {
			Indication indication = simpleReport.getIndication(sigId);
			assertNotNull(indication);
			if (indication != Indication.PASSED) {
				assertNotNull(simpleReport.getSubIndication(sigId));
			}
			assertNotNull(simpleReport.getSignatureQualification(sigId));
		}
		assertNotNull(simpleReport.getValidationTime());
	}

	protected void verifyDetailedReport(DetailedReport detailedReport) {
		assertNotNull(detailedReport);

		int nbBBBs = detailedReport.getBasicBuildingBlocksNumber();
		assertTrue(nbBBBs > 0);
		for (int i = 0; i < nbBBBs; i++) {
			String id = detailedReport.getBasicBuildingBlocksSignatureId(i);
			assertNotNull(id);
			assertNotNull(detailedReport.getBasicBuildingBlocksIndication(id));
		}

		List<String> signatureIds = detailedReport.getSignatureIds();
		assertTrue(Utils.isCollectionNotEmpty(signatureIds));
		for (String sigId : signatureIds) {
			Indication basicIndication = detailedReport.getBasicValidationIndication(sigId);
			assertNotNull(basicIndication);
			if (!Indication.PASSED.equals(basicIndication)) {
				assertNotNull(detailedReport.getBasicValidationSubIndication(sigId));
			}
		}

		List<String> timestampIds = detailedReport.getTimestampIds();
		if (Utils.isCollectionNotEmpty(timestampIds)) {
			for (String tspId : timestampIds) {
				Indication timestampIndication = detailedReport.getTimestampValidationIndication(tspId);
				assertNotNull(timestampIndication);
				if (!Indication.PASSED.equals(timestampIndication)) {
					assertNotNull(detailedReport.getTimestampValidationSubIndication(tspId));
				}
			}
		}

		for (String sigId : signatureIds) {
			Indication ltvIndication = detailedReport.getLongTermValidationIndication(sigId);
			assertNotNull(ltvIndication);
			if (!Indication.PASSED.equals(ltvIndication)) {
				assertNotNull(detailedReport.getLongTermValidationSubIndication(sigId));
			}
		}

		for (String sigId : signatureIds) {
			Indication archiveDataIndication = detailedReport.getArchiveDataValidationIndication(sigId);
			assertNotNull(archiveDataIndication);
			if (!Indication.PASSED.equals(archiveDataIndication)) {
				assertNotNull(detailedReport.getArchiveDataValidationSubIndication(sigId));
			}
		}
	}

	protected abstract SP getExtensionParameters();

	private void checkOriginalLevel(DiagnosticData diagnosticData) {
		assertEquals(getOriginalSignatureLevel().toString(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

	private void checkFinalLevel(DiagnosticData diagnosticData) {
		assertEquals(getFinalSignatureLevel().toString(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

	private void checkBLevelValid(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	private void checkTLevelAndValid(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isThereTLevel(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

}
