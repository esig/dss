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
package eu.europa.esig.dss.cades.extension;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CAdESExtensionDetachedWithContentTimestampTest extends PKIFactoryAccess {

	@Test
	void extend() {

		DSSDocument detachedFile = new InMemoryDocument("hello".getBytes());

		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

		CAdESService service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		TimestampToken contentTimestamp = service.getContentTimestamp(detachedFile, signatureParameters);
		signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp));

		ToBeSigned dataToSign = service.getDataToSign(detachedFile, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				getPrivateKeyEntry());
		DSSDocument signDocument = service.signDocument(detachedFile, signatureParameters, signatureValue);

		validate(signDocument, detachedFile, SignatureLevel.CAdES_BASELINE_B);
	
		// T
		CAdESSignatureParameters extendParams = new CAdESSignatureParameters();
		extendParams.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);
		extendParams.setDetachedContents(Arrays.asList(detachedFile));
		DSSDocument extendDocument = service.extendDocument(signDocument, extendParams);

		validate(extendDocument, detachedFile, SignatureLevel.CAdES_BASELINE_T);

		// LT
		extendParams = new CAdESSignatureParameters();
		extendParams.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
		extendParams.setDetachedContents(Arrays.asList(detachedFile));
		extendDocument = service.extendDocument(signDocument, extendParams);

		validate(extendDocument, detachedFile, SignatureLevel.CAdES_BASELINE_LT);

		// LTA
		extendParams = new CAdESSignatureParameters();
		extendParams.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		extendParams.setDetachedContents(Arrays.asList(detachedFile));
		extendDocument = service.extendDocument(signDocument, extendParams);

		validate(extendDocument, detachedFile, SignatureLevel.CAdES_BASELINE_LTA);
	}

	private void validate(DSSDocument signature, DSSDocument detachedFile, SignatureLevel expectedLevel) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signature);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		validator.setDetachedContents(Arrays.asList(detachedFile));
		Reports reports = validator.validateDocument();

		assertNotNull(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(1, diagnosticData.getAllSignatures().size());

		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureWrapper.isBLevelTechnicallyValid());
		assertEquals(expectedLevel, signatureWrapper.getSignatureFormat());

		List<TimestampWrapper> contentTimestamps = signatureWrapper.getContentTimestamps();
		assertEquals(1, contentTimestamps.size());

		List<TimestampWrapper> timestampList = signatureWrapper.getTimestampList();
		for (TimestampWrapper timestampWrapper : timestampList) {
			assertTrue(timestampWrapper.isMessageImprintDataFound());
			assertTrue(timestampWrapper.isMessageImprintDataIntact());
			assertTrue(timestampWrapper.isSignatureValid());
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
