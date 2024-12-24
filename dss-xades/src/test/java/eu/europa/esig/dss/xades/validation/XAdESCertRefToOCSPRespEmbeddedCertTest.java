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

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.OrphanCertificateTokenWrapper;
import eu.europa.esig.dss.diagnostic.OrphanRevocationTokenWrapper;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESCertRefToOCSPRespEmbeddedCertTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument(new File("src/test/resources/validation/Signature-X-RO_TRA-4.xml"));
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(2, signatures.size());
		boolean signatureFound = false;
		for (SignatureWrapper signature : signatures) {
			if ("Signature-2064753652".equals(signature.getDAIdentifier())) {
				int completeCertificateRefsCounter = 0;
				for (RelatedCertificateWrapper foundCertificate : signature.foundCertificates().getRelatedCertificates()) {
					List<CertificateRefWrapper> certificateRefs = foundCertificate.getReferences();
					assertEquals(1, certificateRefs.size());
					CertificateRefWrapper xmlCertificateRef = certificateRefs.get(0);
					if (CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS.equals(xmlCertificateRef.getOrigin())) {
						completeCertificateRefsCounter++;
					}
					assertNotNull(foundCertificate.getId());
				}
				assertEquals(3, completeCertificateRefsCounter);
				signatureFound = true;
			}
		}
		assertTrue(signatureFound);
		
		List<OrphanCertificateTokenWrapper> allOrphanCertificates = diagnosticData.getAllOrphanCertificateObjects();
		assertEquals(0, allOrphanCertificates.size());
		List<OrphanRevocationTokenWrapper> allOrphanRevocations = diagnosticData.getAllOrphanRevocationObjects();
		assertEquals(0, allOrphanRevocations.size());
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertFalse(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertFalse(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(4, timestampList.size());
		int archiveTimestampCounter = 0;
		for (TimestampWrapper timestamp : timestampList) {
			List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
			for (XmlTimestampedObject timestampedObject : timestampedObjects) {
				assertNotNull(timestampedObject.getToken());
			}
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
				archiveTimestampCounter++;
				assertEquals(ArchiveTimestampType.XAdES, timestamp.getArchiveTimestampType());
			}
		}
		assertEquals(1, archiveTimestampCounter);
	}
	
	@Override
	protected void checkRevocationData(DiagnosticData diagnosticData) {
		super.checkRevocationData(diagnosticData);
		
		boolean ocspWithOtherIssuerFound = false;

		for (CertificateWrapper certificateWrapper : diagnosticData.getUsedCertificates()) {
			CertificateWrapper signingCertificate = certificateWrapper.getSigningCertificate();
			if (signingCertificate == null) {
				continue;
			}
			
			List<CertificateRevocationWrapper> certificateRevocationData = certificateWrapper.getCertificateRevocationData();
			if (Utils.isCollectionNotEmpty(certificateRevocationData)) {
				for (CertificateRevocationWrapper certificateRevocationWrapper : certificateRevocationData) {
					if (RevocationType.OCSP.equals(certificateRevocationWrapper.getRevocationType())) {
						CertificateWrapper ocspSignCert = certificateRevocationWrapper.getSigningCertificate();
						if (!signingCertificate.getId().equals(ocspSignCert.getId())) {
							ocspWithOtherIssuerFound = true;
						}
					}
				}
			}
		}
		
		assertTrue(ocspWithOtherIssuerFound);
	}

}
