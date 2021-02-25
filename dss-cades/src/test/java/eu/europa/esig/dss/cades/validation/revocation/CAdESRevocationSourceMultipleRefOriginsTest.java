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
package eu.europa.esig.dss.cades.validation.revocation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.cades.validation.AbstractCAdESTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.OrphanRevocationWrapper;
import eu.europa.esig.dss.diagnostic.OrphanTokenWrapper;
import eu.europa.esig.dss.diagnostic.RevocationRefWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;

public class CAdESRevocationSourceMultipleRefOriginsTest extends AbstractCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/Signature-C-X-1.p7m");
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		List<OrphanRevocationWrapper> allFoundRevocations = signature.foundRevocations().getOrphanRevocationData();
		assertEquals(3, allFoundRevocations.size());

		List<RevocationRefWrapper> allFoundRevocationRefs = signature.foundRevocations().getRelatedRevocationRefs();
		assertEquals(0, allFoundRevocationRefs.size());

		List<String> revocationIds = new ArrayList<>();
		for (OrphanRevocationWrapper revocation : allFoundRevocations) {
			assertNotNull(revocation.getRevocationType());
			
			assertFalse(revocationIds.contains(revocation.getId()));
			revocationIds.add(revocation.getId());
			
			List<RevocationRefWrapper> revocationRefs = revocation.getReferences();
			assertEquals(1, revocationRefs.size());
			
			RevocationRefWrapper revocationRef = revocationRefs.get(0);
			assertEquals(1, revocationRef.getOrigins().size());
			assertNotNull(revocationRef.getDigestAlgoAndValue());
			assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestMethod());
			assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestValue());
		}
		
		List<OrphanRevocationWrapper> allOrphanRevocations = diagnosticData.getAllOrphanRevocationObjects();
		assertEquals(0, allOrphanRevocations.size());
		List<OrphanTokenWrapper> allOrphanRevocationRefs = diagnosticData.getAllOrphanRevocationReferences();
		assertEquals(3, allOrphanRevocationRefs.size());
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<OrphanRevocationWrapper> allFoundRevocations = signature.foundRevocations().getOrphanRevocationData();
		List<String> revocationIds = new ArrayList<>();
		for (OrphanRevocationWrapper revocation : allFoundRevocations) {
			revocationIds.add(revocation.getId());
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
					
					List<RevocationRefWrapper> revocationRefs = revocation.getReferences();
					assertEquals(1, revocationRefs.size());
					
					RevocationRefWrapper revocationRef = revocationRefs.get(0);
					assertEquals(1, revocationRef.getOrigins().size());
					assertNotNull(revocationRef.getDigestAlgoAndValue());
					assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestMethod());
					assertNotNull(revocationRef.getDigestAlgoAndValue().getDigestValue());
				}
			} else if (TimestampType.VALIDATION_DATA_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertEquals(0, timestampWrapper.foundRevocations().getOrphanRevocationData().size());
			}
		}
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertEquals(SignatureLevel.CAdES_101733_X, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

}
