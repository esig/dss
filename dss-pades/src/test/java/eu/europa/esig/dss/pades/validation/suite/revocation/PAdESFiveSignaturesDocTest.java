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

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;
import eu.europa.esig.xades.jaxb.xades132.DigestAlgAndValueType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESFiveSignaturesDocTest extends AbstractPAdESTestValidation {
	
	private static byte[] previousSignatureSignerDocumentDigest = null;

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/pades-5-signatures-and-1-document-timestamp.pdf"));
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		List<TimestampWrapper> timestamps = diagnosticData.getTimestampList();		
		assertNotNull(timestamps);
		assertEquals(3, timestamps.size());
		List<String> usedTimestampIds = new ArrayList<>();
		for (TimestampWrapper timestamp : timestamps) {
			assertTrue(timestamp.isSigningCertificateIdentified());
			assertTrue(timestamp.isSigningCertificateReferencePresent());
			
			CertificateRefWrapper signingCertificateReference = timestamp.getSigningCertificateReference();
			assertNotNull(signingCertificateReference);
			assertTrue(signingCertificateReference.isDigestValuePresent());
			assertTrue(signingCertificateReference.isDigestValueMatch());
			assertFalse(signingCertificateReference.isIssuerSerialPresent());
			assertFalse(signingCertificateReference.isIssuerSerialMatch());
			
			assertFalse(usedTimestampIds.contains(timestamp.getId()));
			usedTimestampIds.add(timestamp.getId());
			List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
			List<String> usedTimestampObjectIds = new ArrayList<>();
			for (XmlTimestampedObject timestampedObject : timestampedObjects) {
				assertFalse(usedTimestampObjectIds.contains(timestampedObject.getToken().getId()));
				usedTimestampObjectIds.add(timestampedObject.getToken().getId());
			}
		}
		
		SignatureWrapper secondSignature = diagnosticData.getSignatures().get(1);

		List<TimestampWrapper> secondSignatureTimestamps = secondSignature.getTimestampList();
		assertEquals(2, secondSignatureTimestamps.size());
		TimestampWrapper signatureTimestamp = secondSignatureTimestamps.get(0);
		assertEquals(4, signatureTimestamp.getTimestampedObjects().size());
		assertEquals(TimestampType.SIGNATURE_TIMESTAMP, signatureTimestamp.getType());
        
        TimestampWrapper docTimestamp = null;
        for (TimestampWrapper timestamp : timestamps) {
        	if (TimestampType.DOCUMENT_TIMESTAMP.equals(timestamp.getType())) {
        		assertNull(docTimestamp);
				docTimestamp = timestamp;
        	}
        }
        assertNotNull(docTimestamp);

        List<String> checkedIds = new ArrayList<>();
        assertEquals(5, docTimestamp.getTimestampedSignatures().size());
        checkedIds.add(docTimestamp.getTimestampedSignatures().get(0).getId());
        
        List<SignerDataWrapper> timestampedSignedData = docTimestamp.getTimestampedSignedData();
        assertEquals(6, timestampedSignedData.size());
        for (SignerDataWrapper signerDataWrapper : timestampedSignedData) {
            assertFalse(checkedIds.contains(signerDataWrapper.getId()));
            checkedIds.add(signerDataWrapper.getId());
        }
        
        List<CertificateWrapper> timestampedCertificates = docTimestamp.getTimestampedCertificates();
        assertEquals(18, timestampedCertificates.size());
        for (CertificateWrapper certificateWrapper : timestampedCertificates) {
            assertFalse(checkedIds.contains(certificateWrapper.getId()));
            checkedIds.add(certificateWrapper.getId());
        }
        
        List<RevocationWrapper> timestampedRevocations = docTimestamp.getTimestampedRevocations();
        assertEquals(4, timestampedRevocations.size());
        for (RevocationWrapper revocationWrapper : timestampedRevocations) {
            assertFalse(checkedIds.contains(revocationWrapper.getId()));
            checkedIds.add(revocationWrapper.getId());
        }
        
        List<TimestampWrapper> timestampedTimestamps = docTimestamp.getTimestampedTimestamps();
        assertEquals(2, timestampedTimestamps.size());
        for (TimestampWrapper timestampWrapper : timestampedTimestamps) {
            assertFalse(checkedIds.contains(timestampWrapper.getId()));
            checkedIds.add(timestampWrapper.getId());
        }
        
        assertEquals(31, checkedIds.size());
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertFalse(signatureWrapper.isBLevelTechnicallyValid());
		}
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			assertTrue(signature.isSigningCertificateIdentified());
			assertTrue(signature.isSigningCertificateReferencePresent());
			assertFalse(signature.isSigningCertificateReferenceUnique());
			
			CertificateRefWrapper signingCertificateReference = signature.getSigningCertificateReference();
			assertNotNull(signingCertificateReference);
			assertTrue(signingCertificateReference.isDigestValuePresent());
			assertTrue(signingCertificateReference.isDigestValueMatch());
			assertTrue(signingCertificateReference.isIssuerSerialPresent());
			assertTrue(signingCertificateReference.isIssuerSerialMatch());
		}
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertTrue(!signatureWrapper.isThereTLevel() || signatureWrapper.isTLevelTechnicallyValid());
			assertTrue(!signatureWrapper.isThereALevel() || signatureWrapper.isALevelTechnicallyValid());
		}
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		for (AdvancedSignature signature : advancedSignatures) {
			SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(signature.getId());
			checkRefs(signature.getCertificateSource(), signatureWrapper.foundCertificates());
			
			List<TimestampToken> timestamps = signature.getAllTimestamps();
			for (TimestampToken timestampToken : timestamps) {
				TimestampWrapper timestampWrapper = diagnosticData.getTimestampById(timestampToken.getDSSIdAsString());
				checkRefs(timestampToken.getCertificateSource(), timestampWrapper.foundCertificates());
			}
		}
	}
	
	private void checkRefs(SignatureCertificateSource certificateSource, FoundCertificatesProxy foundCertificates) {
		assertEquals(certificateSource.getSigningCertificateRefs().size(),
				foundCertificates.getRelatedCertificateRefsByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
		assertEquals(certificateSource.getAttributeCertificateRefs().size(),
				foundCertificates.getRelatedCertificateRefsByRefOrigin(CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS).size());
		assertEquals(certificateSource.getCompleteCertificateRefs().size(),
				foundCertificates.getRelatedCertificateRefsByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).size());
		
		assertEquals(certificateSource.getSigningCertificateRefs().size(), 
				getRefs(foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE)).size());
		assertEquals(certificateSource.getAttributeCertificateRefs().size(),
				getRefs(foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS)).size());
		assertEquals(certificateSource.getCompleteCertificateRefs().size(),
				getRefs(foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS)).size());
	}
	
	private List<CertificateRefWrapper> getRefs(List<RelatedCertificateWrapper> certificates) {
		List<CertificateRefWrapper> refs = new ArrayList<>();
		for (RelatedCertificateWrapper certificateWrapper : certificates) {
			refs.addAll(certificateWrapper.getReferences());
		}
		return refs;
	}
	
	@Override
	protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
		super.validateETSISignersDocument(signersDocument);

		assertNotNull(signersDocument);
		DigestAlgAndValueType digestAlgAndValue = getDigestAlgoAndValue(signersDocument);
		assertNotNull(digestAlgAndValue);
		byte[] digestValue = digestAlgAndValue.getDigestValue();
		assertTrue(Utils.isArrayNotEmpty(digestValue));
		assertFalse(Arrays.equals(digestValue, previousSignatureSignerDocumentDigest));
		previousSignatureSignerDocumentDigest = digestValue;
	}

}
