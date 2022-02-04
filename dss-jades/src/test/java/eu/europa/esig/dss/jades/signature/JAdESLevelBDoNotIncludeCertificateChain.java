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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.validation.KidCertificateSource;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JAdESLevelBDoNotIncludeCertificateChain extends AbstractJAdESTestSignature {

	private DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
	private DSSDocument documentToSign;
	private JAdESSignatureParameters signatureParameters;

	@BeforeEach
	public void init() {
		service = new JAdESService(getCompleteCertificateVerifier());
		documentToSign = new FileDocument(new File("src/test/resources/sample.json"));
		signatureParameters = new JAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);

		signatureParameters.setIncludeCertificateChain(false);
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		KidCertificateSource signingCertificateSource = new KidCertificateSource();
		signingCertificateSource.addCertificate(getSigningCert());
		validator.setSigningCertificateSource(signingCertificateSource);
		return validator;
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		AdvancedSignature advancedSignature = advancedSignatures.get(0);
		assertEquals(0, advancedSignature.getCertificates().size());
		
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

		List<RelatedCertificateWrapper> relatedCertificates = signatureWrapper.foundCertificates().getRelatedCertificates();
		assertEquals(1, relatedCertificates.size());
		
		RelatedCertificateWrapper relatedCertificateWrapper = relatedCertificates.get(0);
		assertTrue(Utils.isCollectionEmpty(relatedCertificateWrapper.getOrigins()));

		boolean signCertFound = false;
		boolean keyIdentifierFound = false;
		for (CertificateRefWrapper certificateRefWrapper : relatedCertificateWrapper.getReferences()) {
			if (CertificateRefOrigin.SIGNING_CERTIFICATE.equals(certificateRefWrapper.getOrigin())) {
				signCertFound = true;
			} else if (CertificateRefOrigin.KEY_IDENTIFIER.equals(certificateRefWrapper.getOrigin())) {
				keyIdentifierFound = true;
			}
		}
		assertTrue(signCertFound);
		assertTrue(keyIdentifierFound);
		
		assertEquals(1, signatureWrapper.foundCertificates().getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
		assertEquals(1, signatureWrapper.foundCertificates().getRelatedCertificatesByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER).size());

		assertNotNull(signatureWrapper.getSigningCertificate());
		assertTrue(Utils.isCollectionNotEmpty(signatureWrapper.getCertificateChain()));
	}
	
	@Override
	protected void checkNoDuplicateCompleteCertificates(DiagnosticData diagnosticData) {
		// do nothing
	}
	
	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
