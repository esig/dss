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
package eu.europa.esig.dss.xades.validation.revocation;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESRevocationSourceHUTest extends AbstractXAdESTestValidation {
	
	private static Set<String> revocationIds = new HashSet<>();

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/Signature-X-HU_POL-3.xml");
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		super.verifySourcesAndDiagnosticData(advancedSignatures, diagnosticData);
		
		int revocationSignatureOriginCounter = 0;
		
		Set<RevocationWrapper> revocationData = diagnosticData.getAllRevocationData();
		for (RevocationWrapper revocation : revocationData) {
			assertNotNull(revocation.getRevocationType());
			assertNotNull(revocation.getOrigin());
			if (RevocationOrigin.INPUT_DOCUMENT.equals(revocation.getOrigin())) {
				revocationSignatureOriginCounter++;
			}
			revocationIds.add(revocation.getId());
		}
		assertEquals(4, revocationSignatureOriginCounter);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		assertEquals(0, signature.foundRevocations().getRelatedRevocationsByType(RevocationType.CRL).size());
		assertEquals(4, signature.foundRevocations().getRelatedRevocationsByType(RevocationType.OCSP).size());
		assertEquals(2, signature.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(2, signature.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
		
		for (RevocationWrapper revocation : diagnosticData.getAllRevocationData()) {
			assertNotNull(revocation.foundCertificates());
			assertTrue(Utils.isCollectionNotEmpty(revocation.foundCertificates().getRelatedCertificates()));
			assertTrue(Utils.isCollectionNotEmpty(revocation.foundCertificates().getRelatedCertificateRefs()));
			assertTrue(Utils.isCollectionEmpty(revocation.foundCertificates().getOrphanCertificates()));
			assertTrue(Utils.isCollectionEmpty(revocation.foundCertificates().getOrphanCertificateRefs()));
			
			assertEquals(1, revocation.foundCertificates().getRelatedCertificates().size());
			RelatedCertificateWrapper embeddedCertificate = revocation.foundCertificates().getRelatedCertificates().get(0);
			assertEquals(1, embeddedCertificate.getReferences().size());
			CertificateRefWrapper certificateRefWrapper = embeddedCertificate.getReferences().get(0);
			assertEquals(CertificateRefOrigin.SIGNING_CERTIFICATE, certificateRefWrapper.getOrigin());
			assertTrue(certificateRefWrapper.getSki() != null || certificateRefWrapper.getIssuerName() != null);
			assertEquals(embeddedCertificate.getId(), revocation.getSigningCertificate().getId());
		}
	}
	
	@Override
	protected void verifyReportsData(Reports reports) {
		super.verifyReportsData(reports);
		
		XmlDiagnosticData xmlDiagnosticData = reports.getDiagnosticDataJaxb();
		List<XmlSignature> xmlSignatures = xmlDiagnosticData.getSignatures();
		assertNotNull(xmlSignatures);
		for (XmlSignature xmlSignature : xmlSignatures) {
			List<XmlRelatedRevocation> revocationRefs = xmlSignature.getFoundRevocations().getRelatedRevocations();
			assertNotNull(revocationRefs);
			assertEquals(4, revocationRefs.size());
			for (XmlRelatedRevocation revocation : revocationRefs) {
				assertNotNull(revocation.getRevocation());
				assertNotNull(revocation.getType());
				assertTrue(revocationIds.contains(revocation.getRevocation().getId()));
			}
		}
	}

}
