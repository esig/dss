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
package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.signature.AbstractSignatureParameters;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractXAdESConsecutiveExtension<SP extends AbstractSignatureParameters<XAdESTimestampParameters>> extends PKIFactoryAccess {
	
	protected SignatureLevel signatureLevel;
	protected XAdESService service;
	protected XAdESSignatureParameters signatureParameters;
	
	protected abstract DSSDocument getOriginalDocument();
	protected abstract SignatureLevel getFirstSignSignatureLevel();
	protected abstract SignatureLevel getSecondSignSignatureLevel();
	protected abstract SignatureLevel getThirdSignSignatureLevel();
	protected abstract SignatureLevel getFourthSignSignatureLevel();
	
	@BeforeEach
	void init() {
		signatureLevel = SignatureLevel.XAdES_BASELINE_B;
		
		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);

		service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}
	
	@Test
	public void test() {
		
		DSSDocument originalDocument = getOriginalDocument();
		
		signatureLevel = getFirstSignSignatureLevel();
		DSSDocument firstSigned = signDocument(originalDocument);
		// firstSigned.save("target/" + signatureLevel.toString() + ".xml");
		validateDocument(firstSigned);
		
		signatureLevel = getSecondSignSignatureLevel();
		DSSDocument secondSigned = extendDocument(firstSigned);
		// secondSigned.save("target/" + signatureLevel.toString() + ".xml");
		validateDocument(secondSigned);
		
		signatureLevel = getThirdSignSignatureLevel();
		DSSDocument thirdSigned = extendDocument(secondSigned);
		// thirdSigned.save("target/" + signatureLevel.toString() + ".xml");
		validateDocument(thirdSigned);

		signatureLevel = getFourthSignSignatureLevel();
		DSSDocument fourthSigned = extendDocument(thirdSigned);
		// fourthSigned.save("target/" + signatureLevel.toString() + ".xml");
		validateDocument(fourthSigned);
		
	}
	
	protected DSSDocument signDocument(DSSDocument doc) {
		ToBeSigned dataToSign = service.getDataToSign(doc, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(doc, signatureParameters, signatureValue);
	}
	
	protected DSSDocument extendDocument(DSSDocument doc) {
		return service.extendDocument(doc, signatureParameters);
	}
	
	protected void validateDocument(DSSDocument document) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		checkTimestamps(diagnosticData);
		SimpleReport simpleReport = reports.getSimpleReport();
		assertNotNull(simpleReport);
		DetailedReport detailedReport = reports.getDetailedReport();
		assertNotNull(detailedReport);
		validateDetailedReport(detailedReport);
		assertEquals(signatureLevel, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}
	
	private void checkTimestamps(DiagnosticData diagnosticData) {
		List<TimestampWrapper> allTimestamps = diagnosticData.getTimestampList();
		for (TimestampWrapper timestampWrapper : allTimestamps) {
			assertNotNull(timestampWrapper.getProductionTime());
			assertTrue(timestampWrapper.isMessageImprintDataFound());
			assertTrue(timestampWrapper.isMessageImprintDataIntact());
			assertTrue(timestampWrapper.isSignatureIntact());
			assertTrue(timestampWrapper.isSignatureValid());

			List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
			for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
				assertTrue(xmlDigestMatcher.isDataFound());
				assertTrue(xmlDigestMatcher.isDataIntact());
			}
		}
	}
	
	private void validateDetailedReport(DetailedReport detailedReport) {
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
			assertNotEquals(Indication.FAILED, basicIndication);
			if (!Indication.PASSED.equals(basicIndication)) {
				assertNotNull(detailedReport.getBasicValidationSubIndication(sigId));
			}
		}

		List<String> timestampIds = detailedReport.getTimestampIds();
		if (Utils.isCollectionNotEmpty(timestampIds)) {
			for (String tspId : timestampIds) {
				Indication timestampIndication = detailedReport.getBasicTimestampValidationIndication(tspId);
				assertNotNull(timestampIndication);
				assertNotEquals(Indication.FAILED, timestampIndication);
				if (!Indication.PASSED.equals(timestampIndication)) {
					assertNotNull(detailedReport.getBasicTimestampValidationSubIndication(tspId));
				}
			}
		}

		for (String sigId : signatureIds) {
			Indication ltvIndication = detailedReport.getLongTermValidationIndication(sigId);
			assertNotNull(ltvIndication);
			assertNotEquals(Indication.FAILED, ltvIndication);
			if (!Indication.PASSED.equals(ltvIndication)) {
				assertNotNull(detailedReport.getLongTermValidationSubIndication(sigId));
			}
		}

		for (String sigId : signatureIds) {
			Indication archiveDataIndication = detailedReport.getArchiveDataValidationIndication(sigId);
			assertNotNull(archiveDataIndication);
			assertNotEquals(Indication.FAILED, archiveDataIndication);
			if (!Indication.PASSED.equals(archiveDataIndication)) {
				assertNotNull(detailedReport.getArchiveDataValidationSubIndication(sigId));
			}
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
