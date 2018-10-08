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
package eu.europa.esig.dss.xades.signature;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;

import org.junit.Before;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CRLRef;
import eu.europa.esig.dss.validation.CertificateRef;
import eu.europa.esig.dss.validation.OCSPRef;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class XAdESLevelCTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@Before
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_C);
		signatureParameters.setEn319132(false);

		service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}

	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);

		AdvancedSignature advancedSignature = signatures.get(0);

		List<CertificateRef> certificateRefs = advancedSignature.getCertificateRefs();
		assertTrue(Utils.isCollectionNotEmpty(certificateRefs));
		for (CertificateRef certificateRef : certificateRefs) {
			assertNotNull(certificateRef.getDigestAlgorithm());
			assertNotNull(certificateRef.getIssuerName());
			assertNotNull(certificateRef.getIssuerSerial());
			assertNotNull(certificateRef.getDigestValue());
		}

		List<OCSPRef> ocspRefs = advancedSignature.getOCSPRefs();
		List<CRLRef> crlRefs = advancedSignature.getCRLRefs();

		assertTrue(Utils.isCollectionNotEmpty(ocspRefs) || Utils.isCollectionNotEmpty(crlRefs));

		if (!ocspRefs.isEmpty()) {
			for (OCSPRef ocspRef : ocspRefs) {
				assertNotNull(ocspRef.getDigestAlgorithm());
				assertNotNull(ocspRef.getDigestValue());
			}
		}

		if (!crlRefs.isEmpty()) {
			for (CRLRef crlRef : crlRefs) {
				assertNotNull(crlRef.getDigestAlgorithm());
				assertNotNull(crlRef.getDigestValue());
			}
		}

	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

}
