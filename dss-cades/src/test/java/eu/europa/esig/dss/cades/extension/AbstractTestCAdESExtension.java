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
package eu.europa.esig.dss.cades.extension;

import java.security.cert.X509CRL;
import java.util.Date;

import org.bouncycastle.asn1.x509.CRLReason;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.extension.AbstractTestExtension;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.SignaturePackaging;
import eu.europa.esig.dss.test.gen.CRLGenerator;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockCRLSource;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.test.mock.MockTSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

public abstract class AbstractTestCAdESExtension extends AbstractTestExtension<CAdESSignatureParameters> {

	private X509CRL generatedCRL;

	@Override
	protected DSSDocument getSignedDocument() throws Exception {
		CertificateService certificateService = new CertificateService();

		MockPrivateKeyEntry issuerEntry = certificateService.generateSelfSignedCertificate(SignatureAlgorithm.RSA_SHA256);
		MockPrivateKeyEntry entryUserA = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256, issuerEntry);
		MockPrivateKeyEntry entryUserB = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256, issuerEntry);

		CRLGenerator crlGenerator = new CRLGenerator();
		generatedCRL = crlGenerator.generateCRL(entryUserB.getCertificate().getCertificate(), issuerEntry, new Date(), CRLReason.privilegeWithdrawn);

		DSSDocument document = new InMemoryDocument("Hello world!".getBytes(), "test.bin");

		// Sign
		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(entryUserA.getCertificate());
		signatureParameters.setCertificateChain(entryUserA.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(getOriginalSignatureLevel());

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();

		CAdESService service = new CAdESService(certificateVerifier);
		service.setTspSource(new MockTSPSource(certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA256), new Date()));

		ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);

		SignatureValue signatureValue = sign(signatureParameters.getSignatureAlgorithm(), entryUserA, dataToSign);
		final DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);
		return signedDocument;
	}

	@Override
	protected DocumentSignatureService<CAdESSignatureParameters> getSignatureServiceToExtend() throws Exception {
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setCrlSource(new MockCRLSource(generatedCRL));
		CAdESService service = new CAdESService(certificateVerifier);
		CertificateService certificateService = new CertificateService();
		service.setTspSource(new MockTSPSource(certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA256), new Date()));
		return service;
	}

	@Override
	protected CAdESSignatureParameters getExtensionParameters() {
		CAdESSignatureParameters extensionParameters = new CAdESSignatureParameters();
		extensionParameters.setSignatureLevel(getFinalSignatureLevel());
		return extensionParameters;
	}
}
