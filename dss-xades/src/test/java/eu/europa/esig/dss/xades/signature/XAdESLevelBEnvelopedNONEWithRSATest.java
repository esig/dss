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

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;

import org.junit.Before;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

@RunWith(Parameterized.class)
public class XAdESLevelBEnvelopedNONEWithRSATest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	private final DigestAlgorithm digestAlgo;

	@Parameters(name = "DigestAlgorithm {index} : {0}")
	public static Collection<DigestAlgorithm> data() {
		Collection<DigestAlgorithm> rsaCombinations = new ArrayList<DigestAlgorithm>();
		for (DigestAlgorithm digestAlgorithm : DigestAlgorithm.values()) {
			SignatureAlgorithm algorithm = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.RSA, digestAlgorithm);
			if (algorithm != null && Utils.isStringNotEmpty(algorithm.getXMLId())) {
				rsaCombinations.add(digestAlgorithm);
			}
		}
		return rsaCombinations;
	}

	public XAdESLevelBEnvelopedNONEWithRSATest(DigestAlgorithm digestAlgo) {
		this.digestAlgo = digestAlgo;
	}

	@Before
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setDigestAlgorithm(digestAlgo);

		service = new XAdESService(getCompleteCertificateVerifier());
	}

	@Override
	protected DSSDocument sign() {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);

		// Compute the digest before the signature + encode (specific RSA without PSS)
		byte[] originalDigest = DSSUtils.digest(signatureParameters.getDigestAlgorithm(), dataToSign.getBytes());
		Digest digest = new Digest(signatureParameters.getDigestAlgorithm(),
				DSSUtils.encodeRSADigest(signatureParameters.getDigestAlgorithm(), originalDigest));

		SignatureValue signatureValue = getToken().signDigest(digest, getPrivateKeyEntry());
		return service.signDocument(documentToSign, signatureParameters, signatureValue);
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
