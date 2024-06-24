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

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.OrphanCertificateTokenWrapper;
import eu.europa.esig.dss.diagnostic.OrphanCertificateWrapper;
import eu.europa.esig.dss.diagnostic.OrphanRevocationTokenWrapper;
import eu.europa.esig.dss.diagnostic.OrphanRevocationWrapper;
import eu.europa.esig.dss.diagnostic.OrphanTokenWrapper;
import eu.europa.esig.dss.diagnostic.RevocationRefWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAbstractToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificateToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocationToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESValidationDataRefsTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument(new File("src/test/resources/validation/Signature-X-RO_TRA-15.xml"));
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
												  DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		List<OrphanCertificateWrapper> orphanCertificates = signature.foundCertificates().getOrphanCertificates();
		assertEquals(3, orphanCertificates.size());
		for (OrphanCertificateWrapper orphanCertificate : orphanCertificates) {
			assertNotNull(orphanCertificate.getId());
			assertTrue(Utils.isCollectionEmpty(orphanCertificate.getOrigins()));
			assertEquals(1, orphanCertificate.getReferences().size());
			CertificateRefWrapper xmlCertificateRef = orphanCertificate.getReferences().get(0);
			assertEquals(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS, xmlCertificateRef.getOrigin());
			assertNotNull(xmlCertificateRef.getIssuerSerial());
			assertNotNull(xmlCertificateRef.getDigestAlgoAndValue());
			assertNotNull(xmlCertificateRef.getDigestAlgoAndValue().getDigestMethod());
			assertNotNull(xmlCertificateRef.getDigestAlgoAndValue().getDigestValue());
		}
		
		List<OrphanRevocationWrapper> orphanRevocations = signature.foundRevocations().getOrphanRevocationData();
		assertEquals(3, orphanRevocations.size());
		int ocspRevocationCounter = 0;
		for (OrphanRevocationWrapper orphanRevocation : orphanRevocations) {
			assertNotNull(orphanRevocation.getId());
			assertNotNull(orphanRevocation.getRevocationType());
			if (RevocationType.OCSP.equals(orphanRevocation.getRevocationType())) {
				assertNotNull(orphanRevocation.getReferences().get(0).getProductionTime());
				ocspRevocationCounter++;
			}

			for (RevocationRefWrapper revocationRef : orphanRevocation.getReferences()) {
				assertNotNull(revocationRef.getOrigins());
				assertNotNull(revocationRef.getDigestAlgoAndValue());
				assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestMethod());
				assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestValue());
			}
		}
		assertEquals(1, ocspRevocationCounter);
		
		assertEquals(3, signature.foundRevocations().getOrphanRevocationRefs().size());
		
		List<OrphanCertificateTokenWrapper> allOrphanCertificates = diagnosticData.getAllOrphanCertificateReferences();
		assertEquals(3, allOrphanCertificates.size());
		for (OrphanTokenWrapper orphanCertificate : allOrphanCertificates) {
			assertNotNull(orphanCertificate.getDigestAlgoAndValue());
			assertNotNull(orphanCertificate.getDigestAlgoAndValue().getDigestMethod());
			assertNotNull(orphanCertificate.getDigestAlgoAndValue().getDigestValue());
		}
		
		List<OrphanRevocationTokenWrapper> allOrphanRevocations = diagnosticData.getAllOrphanRevocationReferences();
		assertEquals(3, allOrphanRevocations.size());
		for (OrphanTokenWrapper orphanRevocation : allOrphanRevocations) {
			assertNotNull(orphanRevocation);
			assertTrue(orphanRevocations.contains(orphanRevocation));
			assertNotNull(orphanRevocation.getDigestAlgoAndValue());
			assertNotNull(orphanRevocation.getDigestAlgoAndValue().getDigestMethod());
			assertNotNull(orphanRevocation.getDigestAlgoAndValue().getDigestValue());
		}
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(3, timestampList.size());
		int signatureTimestampCounter = 0;
		int sigAndRefsTimestampCounter = 0;
		int refsOnlyTimestampCounter = 0;
		for (TimestampWrapper timestamp : timestampList) {
			if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestamp.getType())) {
				List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
				assertEquals(3, timestampedObjects.size());
				int signatureTokenCounter = 0;
				int signerDataTokenCounter = 0;
				int certificateTokenCounter = 0;
				for (XmlTimestampedObject timestampedObject : timestampedObjects) {
					XmlAbstractToken token = timestampedObject.getToken();
					assertNotNull(token);
					signatureTokenCounter += token instanceof XmlSignature ? 1 : 0;
					signerDataTokenCounter += token instanceof XmlSignerData ? 1 : 0;
					certificateTokenCounter += token instanceof XmlCertificate ? 1 : 0;
				}
				assertEquals(1, signatureTokenCounter);
				assertEquals(1, signerDataTokenCounter);
				assertEquals(1, certificateTokenCounter);
				signatureTimestampCounter++;
			} else {
				List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
				int orphanCertificateTokenCounter = 0;
				int orphanRevocationTokenCounter = 0;
				for (XmlTimestampedObject timestampedObject : timestampedObjects) {
					XmlAbstractToken token = timestampedObject.getToken();
					assertNotNull(token);
					if (token instanceof XmlOrphanToken) {
						XmlOrphanToken orphanToken = (XmlOrphanToken) token;
						if (orphanToken instanceof XmlOrphanCertificateToken) {
							orphanCertificateTokenCounter++;
						} else if (orphanToken instanceof XmlOrphanRevocationToken) {
							orphanRevocationTokenCounter++;
						}
					}
				}
				assertEquals(3, orphanCertificateTokenCounter);
				assertEquals(3, orphanRevocationTokenCounter);
				if (TimestampType.VALIDATION_DATA_TIMESTAMP.equals(timestamp.getType())) {
					assertEquals(11, timestampedObjects.size());
					sigAndRefsTimestampCounter++;
				} else if (TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP.equals(timestamp.getType())) {
					assertEquals(6, timestampedObjects.size());
					refsOnlyTimestampCounter++;
				}
			}
		}
		assertEquals(1, signatureTimestampCounter);
		assertEquals(1, sigAndRefsTimestampCounter);
		assertEquals(1, refsOnlyTimestampCounter);
	}

}
