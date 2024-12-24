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
package eu.europa.esig.dss.pades.validation.suite.revocation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class PAdESMultiSignedDocRevocTest extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/Signature-P-SK-6.pdf"));
	}
	
	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		super.checkNumberOfSignatures(diagnosticData);

		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertNotNull(signatures);
		assertEquals(2, signatures.size());
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		super.verifySourcesAndDiagnosticData(advancedSignatures, diagnosticData);
		
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		
		SignatureWrapper signatureOne = signatures.get(0);
		assertEquals(2, signatureOne.foundRevocations().getRelatedRevocationData().size());
		assertEquals(2, signatureOne.foundRevocations().getRelatedRevocationsByType(RevocationType.CRL).size());
		assertEquals(0, signatureOne.foundRevocations().getRelatedRevocationsByType(RevocationType.OCSP).size());
		assertEquals(0, signatureOne.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(0, signatureOne.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
		assertEquals(2, signatureOne.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.DSS_DICTIONARY).size());
		
		assertEquals(0, signatureOne.foundRevocations().getRelatedRevocationRefs().size());
		assertEquals("Signature1", signatureOne.getFirstFieldName());
		
		SignatureWrapper signatureTwo = signatures.get(1);
		// no DSS dict after the second signature
		assertEquals(0, signatureTwo.foundRevocations().getRelatedRevocationData().size());
		assertEquals(0, signatureTwo.foundRevocations().getRelatedRevocationsByType(RevocationType.CRL).size());
		assertEquals(0, signatureTwo.foundRevocations().getRelatedRevocationsByType(RevocationType.OCSP).size());
		assertEquals(0, signatureTwo.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(0, signatureTwo.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
		assertEquals(0, signatureTwo.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.DSS_DICTIONARY).size());

		assertEquals(0, signatureTwo.foundRevocations().getRelatedRevocationRefs().size());
		assertEquals(0, signatureTwo.foundRevocations().getOrphanRevocationRefs().size());
		assertEquals("Signature3", signatureTwo.getFirstFieldName());
		
		List<TimestampWrapper> timestamps= diagnosticData.getTimestampList();
		assertNotNull(timestamps);
		assertEquals(2, timestamps.size()); // one timestamp is skipped because of /Type /Sig (see DSS-1899)

		assertEquals(TimestampType.SIGNATURE_TIMESTAMP, timestamps.get(0).getType());
		assertEquals(3, timestamps.get(0).getTimestampedObjects().size());
		assertEquals(1, timestamps.get(0).getTimestampedCertificates().size());
		assertEquals(TimestampType.SIGNATURE_TIMESTAMP, timestamps.get(1).getType());
		assertEquals(3, timestamps.get(1).getTimestampedObjects().size());
		assertEquals(1, timestamps.get(1).getTimestampedCertificates().size());
	}

}
