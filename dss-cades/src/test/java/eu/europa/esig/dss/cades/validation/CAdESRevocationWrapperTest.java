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
package eu.europa.esig.dss.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.OrphanRevocationWrapper;
import eu.europa.esig.dss.diagnostic.OrphanTokenWrapper;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationRefWrappper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class CAdESRevocationWrapperTest extends PKIFactoryAccess {
	
	@Test
	public void revocationValuesTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/Signature-C-HU_POL-3.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports report = validator.validateDocument();
		// report.print();
		DiagnosticData diagnosticData = report.getDiagnosticData();
		int revocationSignatureOriginCounter = 0;
		Set<RevocationWrapper> revocationData = diagnosticData.getAllRevocationData();
		for (RevocationWrapper revocation : revocationData) {
			assertNotNull(revocation.getRevocationType());
			assertNotNull(revocation.getOrigin());
			if (RevocationOrigin.INPUT_DOCUMENT.equals(revocation.getOrigin())) {
				revocationSignatureOriginCounter++;
			}
		}
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		assertEquals(2, revocationSignatureOriginCounter);
		assertEquals(0, signature.foundRevocations().getRelatedRevocationsByType(RevocationType.CRL).size());
		assertEquals(2, signature.foundRevocations().getRelatedRevocationsByType(RevocationType.OCSP).size());
		assertEquals(0, signature.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(2, signature.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.CMS_SIGNED_DATA).size());
		assertEquals(0, signature.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
		assertEquals(0, signature.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.DSS_DICTIONARY).size());
	}
	
	@Test
	public void revocationCRLRefsTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/Signature-C-A-XL-1.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports report = validator.validateDocument();
		// report.print();
		DiagnosticData diagnosticData = report.getDiagnosticData();SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<RelatedRevocationWrapper> foundRevocations = signature.foundRevocations().getRelatedRevocationData();
		assertNotNull(foundRevocations);
		List<RevocationRefWrappper> foundRevocationRefs = signature.foundRevocations().getRelatedRevocationRefs();
		assertEquals(3, foundRevocationRefs.size());
		assertEquals(3, signature.foundRevocations().getRelatedRevocationsByRefOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
		assertEquals(0, signature.foundRevocations().getRelatedRevocationsByRefOrigin(RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS).size());
		assertEquals(0, signature.foundRevocations().getOrphanRevocationData().size());
		for (RevocationRefWrappper revocationRef : foundRevocationRefs) {
			assertNotNull(revocationRef.getDigestAlgoAndValue());
			assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestMethod());
			assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestValue());
			assertNotNull(revocationRef.getOrigins());
		}
	}
	
	@Test
	public void revocationOCSPRefsTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/Signature-15-CBp-LT-2.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports report = validator.validateDocument();
		// report.print();
		DiagnosticData diagnosticData = report.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<RelatedRevocationWrapper> foundRevocations = signature.foundRevocations().getRelatedRevocationData();
		assertEquals(0, foundRevocations.size());
		List<OrphanRevocationWrapper> orphanRevocations = signature.foundRevocations().getOrphanRevocationData();
		assertEquals(3, orphanRevocations.size());
		List<RevocationRefWrappper> foundRevocationRefs = signature.foundRevocations().getOrphanRevocationRefs();
		assertEquals(3, foundRevocationRefs.size());
		assertEquals(3, signature.foundRevocations().getOrphanRevocationsByRefOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
		assertEquals(0, signature.foundRevocations().getOrphanRevocationsByRefOrigin(RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS).size());
		for (RevocationRefWrappper revocationRef : foundRevocationRefs) {
			assertNotNull(revocationRef.getDigestAlgoAndValue());
			assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestMethod());
			assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestValue());
			assertNotNull(revocationRef.getOrigins());
			assertNotNull(revocationRef.getProductionTime());
			assertTrue(Utils.isStringNotEmpty(revocationRef.getResponderIdName()) || Utils.isArrayNotEmpty(revocationRef.getResponderIdKey()));
		}
	}
	
	@Test
	public void revocationRefsWithMultipleOrigins() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/Signature-C-X-1.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports report = validator.validateDocument();

		DiagnosticData diagnosticData = report.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		List<OrphanRevocationWrapper> allFoundRevocations = signature.foundRevocations().getOrphanRevocationData();
		assertEquals(3, allFoundRevocations.size());

		List<RevocationRefWrappper> allFoundRevocationRefs = signature.foundRevocations().getRelatedRevocationRefs();
		assertEquals(0, allFoundRevocationRefs.size());

		List<String> revocationIds = new ArrayList<>();
		for (OrphanRevocationWrapper revocation : allFoundRevocations) {
			assertNotNull(revocation.getRevocationType());
			
			assertFalse(revocationIds.contains(revocation.getId()));
			revocationIds.add(revocation.getId());
			
			List<RevocationRefWrappper> revocationRefs = revocation.getReferences();
			assertEquals(1, revocationRefs.size());
			
			RevocationRefWrappper revocationRef = revocationRefs.get(0);
			assertEquals(1, revocationRef.getOrigins().size());
			assertNotNull(revocationRef.getDigestAlgoAndValue());
			assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestMethod());
			assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestValue());
		}
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		
		for (TimestampWrapper timestampWrapper : timestampList) {
			if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
				List<OrphanRevocationWrapper> timestampAllFoundRevocations = timestampWrapper.foundRevocations().getOrphanRevocationData();
				assertEquals(3, timestampAllFoundRevocations.size());
				for (OrphanRevocationWrapper revocation : timestampAllFoundRevocations) {
					assertNotNull(revocation.getRevocationType());
					
					assertTrue(revocationIds.contains(revocation.getId()));
					
					List<RevocationRefWrappper> revocationRefs = revocation.getReferences();
					assertEquals(1, revocationRefs.size());
					
					RevocationRefWrappper revocationRef = revocationRefs.get(0);
					assertEquals(1, revocationRef.getOrigins().size());
					assertNotNull(revocationRef.getDigestAlgoAndValue());
					assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestMethod());
					assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestValue());
				}
			} else if (TimestampType.VALIDATION_DATA_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertEquals(0, timestampWrapper.foundRevocations().getOrphanRevocationData().size());
			}
		}
		
		List<OrphanRevocationWrapper> allOrphanRevocations = diagnosticData.getAllOrphanRevocationObjects();
		assertEquals(0, allOrphanRevocations.size());
		List<OrphanTokenWrapper> allOrphanRevocationRefs = diagnosticData.getAllOrphanRevocationReferences();
		assertEquals(3, allOrphanRevocationRefs.size());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
