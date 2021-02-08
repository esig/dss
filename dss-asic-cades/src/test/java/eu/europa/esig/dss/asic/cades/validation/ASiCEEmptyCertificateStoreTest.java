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
package eu.europa.esig.dss.asic.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignatureCertificateSource;
import eu.europa.esig.validationreport.jaxb.SignerInformationType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCEEmptyCertificateStoreTest extends AbstractASiCWithCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/emptyCertStore.asice");
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		
		assertEquals(1, signatures.size());
		AdvancedSignature advancedSignature = signatures.get(0);
		assertTrue(Utils.isCollectionEmpty(advancedSignature.getCertificates()));
	}
	
	@Override
	protected void checkTokens(DiagnosticData diagnosticData) {
		super.checkTokens(diagnosticData);
		
		assertEquals(0, diagnosticData.getUsedCertificates().size());
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		AdvancedSignature advancedSignature = advancedSignatures.get(0);
		SignatureCertificateSource certificateSource = advancedSignature.getCertificateSource();
		
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(advancedSignature.getId());
		FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();
		
		assertEquals(certificateSource.getSigningCertificateRefs().size(),
					foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		assertNull(diagnosticData.getSigningCertificateId(diagnosticData.getFirstSignatureId()));

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(EncryptionAlgorithm.RSA, signature.getEncryptionAlgorithm());
		assertEquals("?", signature.getKeyLengthUsedToSignThisToken());
		assertEquals(DigestAlgorithm.SHA256, signature.getDigestAlgorithm());
	}
	
	@Override
	protected void validateSignerInformation(SignerInformationType signerInformation) {
		assertNull(signerInformation);
	}

}
