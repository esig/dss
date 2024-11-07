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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.POEProvisioningType;
import eu.europa.esig.validationreport.jaxb.VOReferenceType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESDoubleLTAValidationDataTest extends PKIFactoryAccess {
	
	@Test
	void test() throws Exception {

		DSSDocument doc = new InMemoryDocument("Hello".getBytes(StandardCharsets.UTF_8));
		
		// Sign with LT level and GoodTSA
		CAdESService service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		CAdESSignatureParameters params = new CAdESSignatureParameters();
		params.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		params.setSigningCertificate(getSigningCert());
		params.setCertificateChain(getCertificateChain());
		params.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);

		ToBeSigned dataToSign = service.getDataToSign(doc, params);

		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument ltLevelDoc = service.signDocument(doc, params, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(ltLevelDoc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		List<AdvancedSignature> signatures = validator.getSignatures();
		AdvancedSignature advancedSignature = signatures.get(0);
		
		assertEquals(1, advancedSignature.getCRLSource().getAllRevocationBinaries().size());
		assertEquals(1, advancedSignature.getOCSPSource().getAllRevocationBinaries().size());
		
		TimestampToken timestampToken = advancedSignature.getSignatureTimestamps().get(0);
		assertEquals(0, timestampToken.getCRLSource().getAllRevocationBinaries().size());
		assertEquals(0, timestampToken.getOCSPSource().getAllRevocationBinaries().size());
		
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<RelatedRevocationWrapper> relatedRevocationData = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId())
				.foundRevocations().getRelatedRevocationData();
		assertEquals(2, relatedRevocationData.size());
		
		// ltLevelDoc.save("target/ltLevelDoc.pkcs7");
		
		// Extend to LTA level with GoodTSACrossCertification
		service.setTspSource(getGoodTsaCrossCertification());

		CAdESSignatureParameters extendParams = new CAdESSignatureParameters();
		extendParams.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		extendParams.setSigningCertificate(getSigningCert());
		DSSDocument ltaDoc = service.extendDocument(ltLevelDoc, extendParams);
		
		// ltaDoc.save("target/ltaDoc.pkcs7");

		validator = SignedDocumentValidator.fromDocument(ltaDoc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		reports = validator.validateDocument();
		
		signatures = validator.getSignatures();
		advancedSignature = signatures.get(0);
		
		assertEquals(1, advancedSignature.getCRLSource().getAllRevocationBinaries().size());
		assertEquals(1, advancedSignature.getOCSPSource().getAllRevocationBinaries().size());
		
		TimestampToken archiveTimestamp = advancedSignature.getArchiveTimestamps().get(0);
		assertEquals(0, archiveTimestamp.getCRLSource().getAllRevocationBinaries().size());
		assertEquals(0, archiveTimestamp.getOCSPSource().getAllRevocationBinaries().size());
		
		extendParams.setCertificateChain(getCertificateChain());
		
		diagnosticData = reports.getDiagnosticData();
		List<RelatedRevocationWrapper> relatedRevocationDataLTALevel = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId())
				.foundRevocations().getRelatedRevocationData();
		assertEquals(2, relatedRevocationDataLTALevel.size());
		for (RevocationWrapper revocationWrapper : relatedRevocationData) {
			assertTrue(relatedRevocationDataLTALevel.contains(revocationWrapper));
		}
		
		// Extend to second LTA level with GoodTSACrossCertification
		// A new revocation data shall be added into the root CMS SignedData
		DSSDocument doubleLtaDoc = service.extendDocument(ltaDoc, extendParams);
		
		// doubleLtaDoc.save("target/doubleLtaDoc.pkcs7");

		validator = SignedDocumentValidator.fromDocument(doubleLtaDoc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		reports = validator.validateDocument();
		
		// reports.print();
		
		signatures = validator.getSignatures();
		advancedSignature = signatures.get(0);
		
		assertEquals(2, advancedSignature.getCRLSource().getAllRevocationBinaries().size());
		assertEquals(1, advancedSignature.getOCSPSource().getAllRevocationBinaries().size());
		
		assertEquals(2, advancedSignature.getCompleteCRLSource().getAllRevocationBinaries().size());
		assertEquals(1, advancedSignature.getCompleteOCSPSource().getAllRevocationBinaries().size());
		
		archiveTimestamp = advancedSignature.getArchiveTimestamps().get(0);
		assertEquals(0, archiveTimestamp.getCRLSource().getAllRevocationBinaries().size());
		assertEquals(0, archiveTimestamp.getOCSPSource().getAllRevocationBinaries().size());
		
		diagnosticData = reports.getDiagnosticData();
		
		List<TimestampWrapper> allTimestamps = diagnosticData.getTimestampList();
		assertNotNull(allTimestamps);
		assertEquals(3, allTimestamps.size());
		
		for (TimestampWrapper timestamp : allTimestamps) {
			CertificateWrapper signingCertificate = timestamp.getSigningCertificate();
			assertNotNull(signingCertificate);
			assertTrue(signingCertificate.isRevocationDataAvailable());
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
		}
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);

		List<TimestampWrapper> timestampList = signature.getTimestampList();
		
		TimestampWrapper signatureTimestampWrapper = timestampList.get(0);
		assertEquals(2, signatureTimestampWrapper.foundCertificates().getRelatedCertificates().size());
		assertEquals(1, signatureTimestampWrapper.foundCertificates().getRelatedCertificateRefs().size());
		assertEquals(0, signatureTimestampWrapper.foundCertificates().getOrphanCertificateRefs().size());
		assertEquals(0, signatureTimestampWrapper.foundRevocations().getRelatedRevocationData().size());
		assertEquals(0, signatureTimestampWrapper.foundRevocations().getRelatedRevocationRefs().size());
		assertEquals(0, signatureTimestampWrapper.foundRevocations().getOrphanRevocationRefs().size());
		assertEquals(0, signatureTimestampWrapper.getTimestampedRevocations().size());
		
		TimestampWrapper archiveTimestampWrapper = timestampList.get(1);
		assertEquals(4, archiveTimestampWrapper.foundCertificates().getRelatedCertificates().size());
		assertEquals(1, archiveTimestampWrapper.foundCertificates().getRelatedCertificateRefs().size());
		assertEquals(0, archiveTimestampWrapper.foundCertificates().getOrphanCertificateRefs().size());
		assertEquals(0, archiveTimestampWrapper.foundRevocations().getRelatedRevocationData().size());
		assertEquals(0, archiveTimestampWrapper.foundRevocations().getRelatedRevocationRefs().size());
		assertEquals(0, archiveTimestampWrapper.foundRevocations().getOrphanRevocationRefs().size());
		assertEquals(2, archiveTimestampWrapper.getTimestampedRevocations().size());

		TimestampWrapper secondArchiveTimestampWrapper = timestampList.get(2);
		assertEquals(4, secondArchiveTimestampWrapper.foundCertificates().getRelatedCertificates().size());
		assertEquals(1, secondArchiveTimestampWrapper.foundCertificates().getRelatedCertificateRefs().size());
		assertEquals(0, secondArchiveTimestampWrapper.foundCertificates().getOrphanCertificateRefs().size());
		assertEquals(0, secondArchiveTimestampWrapper.foundRevocations().getRelatedRevocationData().size());
		assertEquals(0, archiveTimestampWrapper.foundRevocations().getRelatedRevocationRefs().size());
		assertEquals(0, archiveTimestampWrapper.foundRevocations().getOrphanRevocationRefs().size());
		assertEquals(3, secondArchiveTimestampWrapper.getTimestampedRevocations().size());
		
		List<RelatedRevocationWrapper> revocationDataDoubleLtaLevel = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId())
				.foundRevocations().getRelatedRevocationData();
		assertEquals(3, revocationDataDoubleLtaLevel.size());
		for (RevocationWrapper revocation : relatedRevocationDataLTALevel) {
			assertTrue(revocationDataDoubleLtaLevel.contains(revocation));
		}
		
		assertEquals(3, diagnosticData.getAllRevocationData().size());
		
		ValidationReportType etsiValidationReportJaxb = reports.getEtsiValidationReportJaxb();
		List<ValidationObjectType> validationObjects = etsiValidationReportJaxb.getSignatureValidationObjects().getValidationObject();
		int validationReportTimestampCounter = 0;
		for (ValidationObjectType validationObject : validationObjects) {
			
			POEProvisioningType poeProvisioning = validationObject.getPOEProvisioning();
			if (poeProvisioning != null) {
				
				List<String> timestampedObjectIds = new ArrayList<>();
				
				assertNotNull(poeProvisioning.getPOETime());
				assertNotNull(poeProvisioning.getSignatureReference());
				
				validationReportTimestampCounter++;
				List<VOReferenceType> references = poeProvisioning.getValidationObject();
				assertTrue(Utils.isCollectionNotEmpty(references));
				
				for (VOReferenceType reference : references) {
					Object voReference = reference.getVOReference().get(0);
					assertNotNull(voReference);
					assertTrue(voReference instanceof ValidationObjectType);
					ValidationObjectType validationObjectReference = (ValidationObjectType) voReference;
					String id = validationObjectReference.getId();
					assertNotNull(id);
					assertFalse(timestampedObjectIds.contains(id));
					timestampedObjectIds.add(id);
				}
				
				assertTrue(Utils.isCollectionNotEmpty(timestampedObjectIds));
			}
		}
		assertEquals(3, validationReportTimestampCounter);
		
	}

	@Override
	protected String getSigningAlias() {
		return RSA_SHA3_USER;
	}

}
