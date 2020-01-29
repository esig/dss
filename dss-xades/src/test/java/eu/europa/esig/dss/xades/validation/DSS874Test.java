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
package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectListType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

public class DSS874Test {

	@Test
	public void test() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss874/sellosFNMT-XAdES_A.xml");
		File policyDocument = new File("src/test/resources/validation/dss874/policy.pdf");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
		Map<String, DSSDocument> signaturePoliciesById = new HashMap<>();
		signaturePoliciesById.put("2.16.724.1.3.1.1.2.1.9", new FileDocument(policyDocument));
		signaturePolicyProvider.setSignaturePoliciesById(signaturePoliciesById);
		validator.setSignaturePolicyProvider(signaturePolicyProvider);
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());
		
		String signatureId = diagnosticData.getFirstSignatureId();
		List<DSSDocument> retrievedOriginalDocuments = validator.getOriginalDocuments(signatureId);
		assertEquals(1, retrievedOriginalDocuments.size());

		SignatureWrapper signatureWrapper = signatures.get(0);
		assertTrue(signatureWrapper.isPolicyStatus());
		assertTrue(signatureWrapper.isPolicyIdentified());
		assertEquals("https://sede.060.gob.es/politica_de_firma_anexo_1.pdf", signatureWrapper.getPolicyUrl());
		
		assertEquals(5, signatureWrapper.getRevocationIdsByType(RevocationType.OCSP).size());
		
		assertEquals(5, signatureWrapper.getFoundCertificatesByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).size());
		assertEquals(3, signatureWrapper.getFoundRevocationRefsByOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
		assertEquals(5, signatureWrapper.getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
		assertEquals(5, signatureWrapper.getRevocationIdsByOrigin(RevocationOrigin.REVOCATION_VALUES).size());
		
		assertEquals(3, signatureWrapper.getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(2, signatureWrapper.getOrphanRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES).size());
		
		List<String> revocationIds = signatureWrapper.getRevocationIds();
		
		ValidationReportType etsiValidationReportJaxb = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReportJaxb);
		ValidationObjectListType signatureValidationObjects = etsiValidationReportJaxb.getSignatureValidationObjects();
		List<ValidationObjectType> validationObjects = signatureValidationObjects.getValidationObject();
		
		int ocspRevocationsCounter = 0;
		for (ValidationObjectType validationObject : validationObjects) {
			if (ObjectType.OCSP_RESPONSE.equals(validationObject.getObjectType())) {
				assertTrue(revocationIds.contains(validationObject.getId()));
				ocspRevocationsCounter++;
			}
		}
		
		assertEquals(5, ocspRevocationsCounter);
		
	}

	@Test
	public void test2() throws IOException {
		File policyDocument = new File("src/test/resources/validation/dss874/policy.pdf");
		byte[] byteArray = Utils.toByteArray(new FileInputStream(policyDocument));

		byte[] asn1SignaturePolicyDigest = DSSUtils.digest(DigestAlgorithm.SHA1, byteArray);

		assertEquals("G7roucf600+f03r/o0bAOQ6WAs0=", Base64.getEncoder().encodeToString(asn1SignaturePolicyDigest));
	}

}
