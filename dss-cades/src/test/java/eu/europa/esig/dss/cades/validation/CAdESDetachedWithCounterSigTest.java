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
package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.tsp.TimestampCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESDetachedWithCounterSigTest extends AbstractCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(CAdESDetachedWithCounterSigTest.class.getResourceAsStream("/validation/dss-1892/detached_with_counter_sig.p7m"));
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		return Collections.singletonList(new InMemoryDocument(CAdESDetachedWithCounterSigTest.class.getResourceAsStream("/validation/dss-1892/signed_content.bin")));
	}
	
	@Override
	protected void checkCounterSignatures(DiagnosticData diagnosticData) {
		super.checkCounterSignatures(diagnosticData);
		
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		boolean counterSigFound = false;
		for (SignatureWrapper signature : signatures) {
			if (signature.isCounterSignature()) {
				counterSigFound = true;
			}
			assertEquals(1, signature.getTimestampList().size());
		}
		assertTrue(counterSigFound);
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		for (TimestampWrapper timestampWrapper : timestampList) {
			assertTrue(timestampWrapper.isSigningCertificateIdentified());
			assertTrue(timestampWrapper.isSigningCertificateReferencePresent());
			assertFalse(timestampWrapper.isSigningCertificateReferenceUnique());
			
			CertificateRefWrapper signingCertificateReference = timestampWrapper.getSigningCertificateReference();
			assertNotNull(signingCertificateReference);
			assertTrue(signingCertificateReference.isDigestValuePresent());
			assertTrue(signingCertificateReference.isDigestValueMatch());
			assertTrue(signingCertificateReference.isIssuerSerialPresent());
			assertTrue(signingCertificateReference.isIssuerSerialMatch());
		}
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		for (AdvancedSignature advancedSignature : advancedSignatures) {
			List<TimestampToken> allTimestamps = advancedSignature.getAllTimestamps();
			for (TimestampToken timestampToken : allTimestamps) {
				TimestampCertificateSource certificateSource = timestampToken.getCertificateSource();
				TimestampWrapper timestampWrapper = diagnosticData.getTimestampById(timestampToken.getDSSIdAsString());
				FoundCertificatesProxy foundCertificates = timestampWrapper.foundCertificates();
				
				assertEquals(certificateSource.getSigningCertificateRefs().size(),
						foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size() +
						foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
			}
		}
	}

}
