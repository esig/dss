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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.FoundRevocationsProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS2149WithXAdESTest extends PKIFactoryAccess {
	
	@Test
	void test() {

		DSSDocument documentToSign = new FileDocument("src/test/resources/sample.xml");

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getAlternateGoodTsa());

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		service.setTspSource(getGoodTsa());

		XAdESSignatureParameters extendParameters = new XAdESSignatureParameters();
		extendParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		DSSDocument extendedDocument = service.extendDocument(signedDocument, extendParameters);
		
		DSSDocument doubleLTADoc = service.extendDocument(extendedDocument, extendParameters);
		
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doubleLTADoc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		List<TimestampWrapper> timestampList = signatureWrapper.getTimestampList();
		assertEquals(3, timestampList.size());
		
		FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();
		FoundRevocationsProxy foundRevocations = signatureWrapper.foundRevocations();
		
		List<String> certificateValuesIds = foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES)
				.stream().map(c -> c.getId()).collect(Collectors.toList());
		assertTrue(Utils.isCollectionNotEmpty(certificateValuesIds));
		
		List<String> tstValidationDataCertificateIds = foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA)
				.stream().map(c -> c.getId()).collect(Collectors.toList());
		assertTrue(Utils.isCollectionNotEmpty(tstValidationDataCertificateIds));
		
		// shall not contain duplicates
		certificateValuesIds.retainAll(tstValidationDataCertificateIds);
		assertTrue(Utils.isCollectionEmpty(certificateValuesIds));
		
		List<String> revocationValuesIds = foundRevocations.getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES)
				.stream().map(r -> r.getId()).collect(Collectors.toList());
		assertTrue(Utils.isCollectionNotEmpty(revocationValuesIds));
		
		List<String> tstValidationDataRevocationsIds = foundRevocations.getRelatedRevocationsByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA)
				.stream().map(r -> r.getId()).collect(Collectors.toList());
		assertTrue(Utils.isCollectionNotEmpty(tstValidationDataRevocationsIds));

		// same here
		revocationValuesIds.retainAll(tstValidationDataRevocationsIds);
		assertTrue(Utils.isCollectionEmpty(revocationValuesIds));
		
	}

	@Override
	protected String getSigningAlias() {
		return PSS_GOOD_USER;
	}

}
