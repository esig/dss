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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocationRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class XMLRevocationWrappingTest extends PKIFactoryAccess {
	
	@Test
	public void revocationOriginTest() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/HU_POL/Signature-X-HU_POL-3.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		int revocationSignatureOriginCounter = 0;
		
		Set<RevocationWrapper> revocationData = diagnosticData.getAllRevocationData();
		Set<String> revocationIds = new HashSet<String>();
		for (RevocationWrapper revocation : revocationData) {
			assertNotNull(revocation.getRevocationType());
			assertNotNull(revocation.getOrigin());
			if (RevocationOrigin.SIGNATURE.equals(revocation.getOrigin())) {
				revocationSignatureOriginCounter++;
			}
			revocationIds.add(revocation.getId());
		}
		assertEquals(4, revocationSignatureOriginCounter);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		assertEquals(0, signature.getRevocationIdsByType(RevocationType.CRL).size());
		assertEquals(4, signature.getRevocationIdsByType(RevocationType.OCSP).size());
		assertEquals(2, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(2, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
		
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
	
	@Test
	public void revocationOriginThreeSignaturesTest() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/HR_FIN/Signature-X-HR_FIN-1.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		int revocationSignatureOriginCounter = 0;
		Set<RevocationWrapper> revocationData = diagnosticData.getAllRevocationData();
		Set<String> revocationIds = new HashSet<String>();
		for (RevocationWrapper revocation : revocationData) {
			assertNotNull(revocation.getRevocationType());
			assertNotNull(revocation.getOrigin());
			if (RevocationOrigin.SIGNATURE.equals(revocation.getOrigin())) {
				revocationSignatureOriginCounter++;
			}
			revocationIds.add(revocation.getId());
		}
		assertEquals(1, revocationSignatureOriginCounter);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		assertEquals(1, signature.getRevocationIdsByType(RevocationType.CRL).size());
		assertEquals(0, signature.getRevocationIdsByType(RevocationType.OCSP).size());
		assertEquals(1, signature.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(0, signature.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
		
		XmlDiagnosticData xmlDiagnosticData = reports.getDiagnosticDataJaxb();
		List<XmlSignature> xmlSignatures = xmlDiagnosticData.getSignatures();
		assertNotNull(xmlSignatures);
		for (XmlSignature xmlSignature : xmlSignatures) {
			List<XmlRelatedRevocation> revocationRefs = xmlSignature.getFoundRevocations().getRelatedRevocations();
			assertNotNull(revocationRefs);
			for (XmlRelatedRevocation revocation : revocationRefs) {
				assertNotNull(revocation.getRevocation());
				assertNotNull(revocation.getType());
				assertTrue(revocationIds.contains(revocation.getRevocation().getId()));
			}
		}
		
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(3, signatures.size());
		
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertEquals(1, signatureWrapper.getAllFoundRevocations().size());
		}
		
		// Same CRL has been inserted 3 times
		assertEquals(1, diagnosticData.getAllRevocationData().size());

	}
	
	@Test
	public void revocationReferencesTest() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/ES/Signature-X-ES-100.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(4, signature.getRelatedRevocations().size());
		assertEquals(4, signature.getFoundRevocationRefsByOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
		assertEquals(0, signature.getFoundRevocationRefsByOrigin(RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS).size());
		int ocspResponses = 0;
		List<String> revocationDigests = new ArrayList<String>();
		for (XmlRevocationRef revocationRef : signature.getFoundRevocationRefsByOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS)) {
			assertNotNull(revocationRef.getDigestAlgoAndValue());
			assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestMethod());
			assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestValue());
			assertNotNull(revocationRef.getOrigins());
			if (revocationRef.getProducedAt() != null) {
				assertTrue(Utils.isStringNotEmpty(revocationRef.getResponderIdName()) || Utils.isArrayNotEmpty(revocationRef.getResponderIdKey()));
				ocspResponses++;
			}
			String base64 = Utils.toBase64(revocationRef.getDigestAlgoAndValue().getDigestValue());
			assertFalse(revocationDigests.contains(base64));
			revocationDigests.add(base64);
		}
		assertEquals(signature.getRevocationIdsByType(RevocationType.OCSP).size(), ocspResponses);
	}
	
	@Test
	public void ocspWrongRefTest() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/BG/Signature-X-BG-1.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlRevocationRef> foundRevocationRefs = signature.getAllFoundRevocationRefs();
		assertNotNull(foundRevocationRefs);
		assertEquals(0, foundRevocationRefs.size());
		List<XmlRevocationRef> relatedRevocationRefs = signature.getAllRelatedRevocationRefs();
		assertNotNull(relatedRevocationRefs);
		assertEquals(0, relatedRevocationRefs.size());
		assertEquals(0, signature.getFoundRevocationRefsByOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
		assertEquals(0, signature.getFoundRevocationRefsByOrigin(RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS).size());
	}
	
	@Test
	public void ocspRefWithByKeyResponderIdTest() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/UK_ELD/Signature-X-UK_ELD-4.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(1, signature.getRelatedRevocations().size());
		assertEquals(0, signature.getOrphanRevocations().size());
		assertEquals(1, signature.getFoundRevocationRefsByOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
		assertEquals(0, signature.getFoundRevocationRefsByOrigin(RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS).size());
		XmlRevocationRef revocationRef = signature.getRelatedRevocations().get(0).getRevocationRefs().get(0);
		assertNotNull(revocationRef.getOrigins());
		assertNotNull(revocationRef.getDigestAlgoAndValue());
		assertNotNull(revocationRef.getProducedAt());
		assertNotNull(revocationRef.getResponderIdKey());
	}
	
	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
