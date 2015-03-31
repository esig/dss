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
package eu.europa.ec.markt.dss.extension.xades;

import java.io.File;
import java.util.Date;

import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.extension.AbstractTestExtension;
import eu.europa.ec.markt.dss.mock.MockTSPSource;
import eu.europa.ec.markt.dss.parameter.XAdESSignatureParameters;
import eu.europa.ec.markt.dss.service.CertificateService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DocumentSignatureService;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.xades.XAdESService;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;

public abstract class AbstractTestXAdESExtension extends AbstractTestExtension<XAdESSignatureParameters> {

	@Override
	protected DSSDocument getSignedDocument() throws Exception {
		CertificateService certificateService = new CertificateService();
		DSSPrivateKeyEntry entryUserA = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		DSSDocument document = new FileDocument(new File("src/test/resources/sample.xml"));

		// Sign
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(entryUserA.getCertificate());
		signatureParameters.setCertificateChain(entryUserA.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(getOriginalSignatureLevel());

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(certificateVerifier);
		service.setTspSource(new MockTSPSource(certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA1), new Date()));

		byte[] dataToSign = service.getDataToSign(document, signatureParameters);
		byte[] signatureValue = sign(signatureParameters.getSignatureAlgorithm(), entryUserA.getPrivateKey(), dataToSign);
		final DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);
		return signedDocument;
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters> getSignatureServiceToExtend() throws Exception {
		XAdESService service = new XAdESService(new CommonCertificateVerifier());
		CertificateService certificateService = new CertificateService();
		service.setTspSource(new MockTSPSource(certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA1), new Date()));
		return service;
	}

	protected XAdESSignatureParameters getExtensionParameters() {
		XAdESSignatureParameters extensionParameters = new XAdESSignatureParameters();
		extensionParameters.setSignatureLevel(getFinalSignatureLevel());
		return extensionParameters;
	}

}
