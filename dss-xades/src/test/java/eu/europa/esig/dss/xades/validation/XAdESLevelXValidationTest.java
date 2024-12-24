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
package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.OrphanCertificateWrapper;
import eu.europa.esig.dss.diagnostic.OrphanRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;

class XAdESLevelXValidationTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument(new File("src/test/resources/validation/xades-x-level.xml"));
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signatureWrapper);
		
		List<RelatedCertificateWrapper> relatedCertificates = signatureWrapper.foundCertificates().getRelatedCertificates();
		assertNotNull(relatedCertificates);
		assertEquals(3, relatedCertificates.size());
		for (RelatedCertificateWrapper relatedCertificate : relatedCertificates) {
			assertNotNull(relatedCertificate.getId());
		}
		
		List<OrphanCertificateWrapper> orphanCertificates = signatureWrapper.foundCertificates().getOrphanCertificates();
		assertNotNull(orphanCertificates);
		assertEquals(1, orphanCertificates.size());
		
		List<RelatedCertificateWrapper> completeCertificateRefs = signatureWrapper.foundCertificates()
				.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS);
		assertNotNull(completeCertificateRefs);
		assertEquals(2, completeCertificateRefs.size());
		
		List<OrphanCertificateWrapper> completeOrphanCertificateRefs = signatureWrapper.foundCertificates()
				.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS);
		assertNotNull(completeOrphanCertificateRefs);
		assertEquals(1, completeOrphanCertificateRefs.size());
		
		List<RelatedRevocationWrapper> completeRevocationRefs = signatureWrapper.foundRevocations()
				.getRelatedRevocationsByRefOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
		assertNotNull(completeRevocationRefs);
		assertEquals(0, completeRevocationRefs.size());
		
		List<OrphanRevocationWrapper> orphanCompleteRevocationRefs = signatureWrapper.foundRevocations()
				.getOrphanRevocationsByRefOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
		assertNotNull(orphanCompleteRevocationRefs);
		assertEquals(2, orphanCompleteRevocationRefs.size());
		
		List<OrphanRevocationWrapper> completeCRLRefs = signatureWrapper.foundRevocations().getOrphanRevocationsByType(RevocationType.CRL);
		assertNotNull(completeCRLRefs);
		assertEquals(1, completeCRLRefs.size());
		
		List<OrphanRevocationWrapper> completeOCSPRefs = signatureWrapper.foundRevocations().getOrphanRevocationsByType(RevocationType.OCSP);
		assertNotNull(completeOCSPRefs);
		assertEquals(1, completeOCSPRefs.size());
	}

}
