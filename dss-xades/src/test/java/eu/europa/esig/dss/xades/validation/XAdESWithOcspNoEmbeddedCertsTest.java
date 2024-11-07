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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;

class XAdESWithOcspNoEmbeddedCertsTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/xades-ocsp-not-embeds-certs.xml");
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		super.verifySourcesAndDiagnosticData(advancedSignatures, diagnosticData);
		
		Set<RevocationWrapper> allRevocationData = diagnosticData.getAllRevocationData();
		assertEquals(2, allRevocationData.size());
		List<String> certIds = new ArrayList<>();
		for (RevocationWrapper revocationWrapper : diagnosticData.getAllRevocationData()) {
			assertEquals(RevocationType.OCSP, revocationWrapper.getRevocationType());
			assertNotNull(revocationWrapper.foundCertificates());
			assertEquals(1, revocationWrapper.foundCertificates().getRelatedCertificates().size());
			assertEquals(0, revocationWrapper.foundCertificates().getOrphanCertificates().size());
			assertEquals(1, revocationWrapper.foundCertificates().getRelatedCertificateRefs().size());
			assertEquals(0, revocationWrapper.foundCertificates().getOrphanCertificateRefs().size());
			
			List<RelatedCertificateWrapper> signingCerts = revocationWrapper.foundCertificates()
					.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
			assertEquals(1, signingCerts.size());
			RelatedCertificateWrapper signingCertificate = signingCerts.get(0);
			assertTrue(Utils.isCollectionEmpty(signingCertificate.getOrigins()));
			
			assertNotNull(revocationWrapper.getSigningCertificate());
			assertTrue(Utils.isCollectionNotEmpty(revocationWrapper.getCertificateChain()));
			assertEquals(signingCertificate.getId(), revocationWrapper.getSigningCertificate().getId());
			certIds.add(signingCertificate.getId());
		}
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<RelatedCertificateWrapper> relatedCertificates = signature.foundCertificates().getRelatedCertificates();
		List<String> foundCertIds = relatedCertificates.stream().map(RelatedCertificateWrapper::getId).collect(Collectors.toList());
		for (String id : certIds) {
			assertTrue(foundCertIds.contains(id));
		}
	}
	
	@Override
	protected void checkRevocationData(DiagnosticData diagnosticData) {
		for (RevocationWrapper revocationWrapper : diagnosticData.getAllRevocationData()) {
			assertEquals(0, revocationWrapper.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.BASIC_OCSP_RESP).size());
			assertEquals(0, revocationWrapper.foundCertificates().getOrphanCertificatesByOrigin(CertificateOrigin.BASIC_OCSP_RESP).size());
		}
	}

}
