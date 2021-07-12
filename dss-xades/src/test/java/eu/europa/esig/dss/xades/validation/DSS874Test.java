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
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS874Test extends AbstractXAdESTestValidation {
	
    private static final File policyDocument = new File("src/test/resources/validation/dss874/policy.pdf");

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss874/sellosFNMT-XAdES_A.xml");
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
		Map<String, DSSDocument> signaturePoliciesById = new HashMap<>();
		signaturePoliciesById.put("2.16.724.1.3.1.1.2.1.9", new FileDocument(policyDocument));
		signaturePolicyProvider.setSignaturePoliciesById(signaturePoliciesById);
		validator.setSignaturePolicyProvider(signaturePolicyProvider);
		return validator;
	}
	
	@Override
	protected void checkTokens(DiagnosticData diagnosticData) {
		super.checkTokens(diagnosticData);

		SignatureWrapper signatureWrapper = diagnosticData.getSignatures().get(0);
		assertTrue(signatureWrapper.isPolicyDigestValid());
		assertTrue(signatureWrapper.isPolicyIdentified());
		assertEquals("https://sede.060.gob.es/politica_de_firma_anexo_1.pdf", signatureWrapper.getPolicyUrl());
		
		assertEquals(5, signatureWrapper.foundRevocations().getRelatedRevocationsByType(RevocationType.OCSP).size());
		assertEquals(0, signatureWrapper.foundRevocations().getOrphanRevocationsByType(RevocationType.OCSP).size());
		
		assertEquals(5, signatureWrapper.foundCertificates().getRelatedCertificatesByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).size());
		assertEquals(3, signatureWrapper.foundRevocations().getRelatedRevocationsByRefOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
		assertEquals(0, signatureWrapper.foundRevocations().getOrphanRevocationsByRefOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
		
		assertEquals(5, signatureWrapper.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
		assertEquals(0, signatureWrapper.foundCertificates().getOrphanCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
		
		assertEquals(5, signatureWrapper.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(0, signatureWrapper.foundRevocations().getOrphanRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES).size());
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		super.verifyOriginalDocuments(validator, diagnosticData);
		
		List<DSSDocument> retrievedOriginalDocuments = validator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
		assertEquals(1, retrievedOriginalDocuments.size());
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void policyTest() throws IOException {
		byte[] byteArray = Utils.toByteArray(new FileInputStream(policyDocument));

		byte[] asn1SignaturePolicyDigest = DSSUtils.digest(DigestAlgorithm.SHA1, byteArray);

		assertEquals("G7roucf600+f03r/o0bAOQ6WAs0=", Base64.getEncoder().encodeToString(asn1SignaturePolicyDigest));
	}

}
