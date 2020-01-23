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
package eu.europa.esig.dss.cades.signature;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;

@RunWith(Parameterized.class)
public class CAdESLevelBNONEWithRSATest extends AbstractCAdESTestSignature {

	private static final String HELLO_WORLD = "Hello World";

	private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
	private CAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	private final DigestAlgorithm messageDigestAlgo;
	private final DigestAlgorithm digestAlgo;

	@Parameters(name = "Combination {index} of message-digest algorithm {0} + digest algorithm {1}")
	public static Collection<Object[]> data() {

		List<Object[]> digests = new ArrayList<>();
		
		List<DigestAlgorithm> digestAlgos = Arrays.asList(DigestAlgorithm.SHA224,
				DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512, DigestAlgorithm.SHA3_224,
				DigestAlgorithm.SHA3_256, DigestAlgorithm.SHA3_384, DigestAlgorithm.SHA3_512);
		for (DigestAlgorithm digest1 : digestAlgos) {
			for (DigestAlgorithm digest2 : digestAlgos) {
				digests.add(new Object[] { digest1, digest2 });
			}
		}
		
		List<DigestAlgorithm> messageDigestAlgos = Arrays.asList(DigestAlgorithm.RIPEMD160,
				DigestAlgorithm.MD2, DigestAlgorithm.MD5);
		for (DigestAlgorithm digest1 : messageDigestAlgos) {
			digests.add(new Object[] { digest1, digest1 });
			for (DigestAlgorithm digest2 : digestAlgos) {
				digests.add(new Object[] { digest1, digest2 });
			}
		}
		
		// DigestAlgorithm.WHIRLPOOL
		for (DigestAlgorithm digest : digestAlgos) {
			digests.add(new Object[] { DigestAlgorithm.WHIRLPOOL, digest });
		}

		// Due to
		// org.bouncycastle.cms.DefaultCMSSignatureEncryptionAlgorithmFinder.findEncryptionAlgorithm(AlgorithmIdentifier)
		List<DigestAlgorithm> digestAlgosWithSha1 = new ArrayList<>(digestAlgos);
		digestAlgosWithSha1.add(DigestAlgorithm.SHA1);
		for (DigestAlgorithm digest : digestAlgosWithSha1) {
			digests.add(new Object[] { DigestAlgorithm.SHA1, digest });
		}
		
		return digests;
	}

	public CAdESLevelBNONEWithRSATest(DigestAlgorithm messageDigestAlgo, DigestAlgorithm digestAlgo) {
		this.messageDigestAlgo = messageDigestAlgo;
		this.digestAlgo = digestAlgo;
	}

	@Before
	public void init() throws Exception {
		documentToSign = new InMemoryDocument(HELLO_WORLD.getBytes(),
				"BC-CAdES-BpB-att-" + messageDigestAlgo.name() + "-" + digestAlgo.name() + "withRSA.p7m");

		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.setReferenceDigestAlgorithm(messageDigestAlgo);
		signatureParameters.setDigestAlgorithm(digestAlgo);

		service = new CAdESService(getOfflineCertificateVerifier());
	}
	
	// Annotation JUnit 4
	@Test
	@Override
	public void signAndVerify() throws IOException {
		super.signAndVerify();
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
	protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected CAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
