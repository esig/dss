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
package eu.europa.esig.dss.pades.signature.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class PAdESDoubleLTAValidationDataTest extends PKIFactoryAccess {
	
	@Test
	public void test() throws Exception {

		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
		
		// Sign with LT level and GoodTSA
		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		PAdESSignatureParameters params = new PAdESSignatureParameters();
		params.setSigningCertificate(getSigningCert());
		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);

		ToBeSigned dataToSign = service.getDataToSign(doc, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument ltLevelDoc = service.signDocument(doc, params, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(ltLevelDoc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		List<AdvancedSignature> signatures = validator.getSignatures();
		AdvancedSignature advancedSignature = signatures.get(0);
		
		assertEquals(1, advancedSignature.getCRLSource().getCRLBinaryList().size());
		assertEquals(1, advancedSignature.getOCSPSource().getOCSPResponsesList().size());
		
		Reports reports = validator.validateDocument();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<String> revocationIds = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId()).getRevocationIds();
		assertEquals(2, revocationIds.size());
		
		List<TimestampWrapper> timestamps = diagnosticData.getTimestampList();
		assertEquals(1, timestamps.size());
		assertEquals(0, timestamps.get(0).getTimestampedRevocationIds().size());
		

		// Extend to LTA level with GoodTSACrossCertification
		service.setTspSource(getGoodTsaCrossCertification());
		
		PAdESSignatureParameters extendParams = new PAdESSignatureParameters();
		extendParams.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		extendParams.setSigningCertificate(getSigningCert());
		DSSDocument ltaDoc = service.extendDocument(ltLevelDoc, extendParams);

		validator = SignedDocumentValidator.fromDocument(ltaDoc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		reports = validator.validateDocument();
		
		signatures = validator.getSignatures();
		advancedSignature = signatures.get(0);
		
		assertEquals(1, advancedSignature.getCRLSource().getCRLBinaryList().size());
		assertEquals(1, advancedSignature.getOCSPSource().getOCSPResponsesList().size());
		
		diagnosticData = reports.getDiagnosticData();
		List<String> revocationIdsLtaLevel = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId()).getRevocationIds();
		assertEquals(2, revocationIdsLtaLevel.size());
		for (String id : revocationIds) {
			assertTrue(revocationIdsLtaLevel.contains(id));
		}
		
		timestamps = diagnosticData.getTimestampList();
		assertEquals(2, timestamps.size());
		assertEquals(0, timestamps.get(0).getTimestampedRevocationIds().size());
		
		assertEquals(2, timestamps.get(1).getTimestampedRevocationIds().size());
		
		
		// Extend to second LTA level with GoodTSACrossCertification
		// This must force addition of missing revocation data to the previously created timestamp
		DSSDocument doubleLtaDoc = service.extendDocument(ltaDoc, extendParams);
		
		// doubleLtaDoc.save("target/doubleLtaDoc.pdf");

		validator = SignedDocumentValidator.fromDocument(doubleLtaDoc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		reports = validator.validateDocument();
		
		// reports.print();
		
		signatures = validator.getSignatures();
		advancedSignature = signatures.get(0);
		
		assertEquals(2, advancedSignature.getCRLSource().getCRLBinaryList().size());
		assertEquals(1, advancedSignature.getOCSPSource().getOCSPResponsesList().size());
		
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
		diagnosticData = reports.getDiagnosticData();
		
		timestamps = diagnosticData.getTimestampList();
		assertNotNull(timestamps);
		assertEquals(3, timestamps.size());
		
		int archiveTimestampCounter = 0;
		for (TimestampWrapper timestamp : timestamps) {
			CertificateWrapper signingCertificate = timestamp.getSigningCertificate();
			assertNotNull(signingCertificate);
			assertTrue(signingCertificate.isRevocationDataAvailable());
			assertTrue(timestamp.getDigestMatchers().get(0).isDataFound());
			assertTrue(timestamp.getDigestMatchers().get(0).isDataIntact());
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
				assertEquals(ArchiveTimestampType.PAdES, timestamp.getArchiveTimestampType());
				archiveTimestampCounter++;
			}
		}
		assertEquals(2, archiveTimestampCounter);
		
		TimestampWrapper timestampWrapper = timestamps.get(0);
		assertEquals(0, timestampWrapper.getTimestampedRevocationIds().size());
		
		timestampWrapper = timestamps.get(1);
		assertEquals(2, timestampWrapper.getTimestampedRevocationIds().size());
		
		timestampWrapper = timestamps.get(2);
		assertEquals(3, timestampWrapper.getTimestampedRevocationIds().size());
		
		List<String> revocationIdsDoubleLtaLevel = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId()).getRevocationIds();
		assertEquals(3, revocationIdsDoubleLtaLevel.size());
		for (String id : revocationIdsLtaLevel) {
			assertTrue(revocationIdsDoubleLtaLevel.contains(id));
		}
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		assertEquals(3, signature.getRevocationIdsByOrigin(RevocationOrigin.DSS_DICTIONARY).size());
		assertEquals(3, signature.getRevocationIdsByOrigin(RevocationOrigin.VRI_DICTIONARY).size());
		
        assertContainsAllRevocationData(signature.getCertificateChain());
        for (TimestampWrapper timestamp : timestamps) {
        	assertContainsAllRevocationData(timestamp.getCertificateChain());
        }
        for (RevocationWrapper revocation : diagnosticData.getAllRevocationData()) {
        	assertContainsAllRevocationData(revocation.getCertificateChain());
        }
		
	}
	
	private void assertContainsAllRevocationData(List<CertificateWrapper> certificateChain) {
        for (CertificateWrapper certificate : certificateChain) {
        	if (certificate.isTrusted()) {
        		break;
        	}
        	assertTrue(certificate.isRevocationDataAvailable() || certificate.isSelfSigned(), 
        			"Certificate with id : [" + certificate.getId() + "] does not have a revocation data!");
        }
	}

	@Override
	protected String getSigningAlias() {
		return RSA_SHA3_USER;
	}


}
