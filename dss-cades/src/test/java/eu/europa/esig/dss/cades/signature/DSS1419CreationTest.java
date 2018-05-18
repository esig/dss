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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.junit.Before;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MaskGenerationFunction;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;

@RunWith(Parameterized.class)
public class DSS1419CreationTest extends AbstractCAdESTestSignature {

	private static final String HELLO_WORLD = "Hello World";

	private DocumentSignatureService<CAdESSignatureParameters> service;
	private CAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	private final DigestAlgorithm messageDigestAlgo;
	private final DigestAlgorithm digestAlgo;
	private final MaskGenerationFunction maskGenerationFunction;

	@Parameters(name = "Combination {index} of message-digest algorithm {0} + digest algorithm {1} + MGF1 ? {2}")
	public static Collection<Object[]> data() {
		List<DigestAlgorithm> digestAlgos = Arrays.asList(DigestAlgorithm.SHA1, DigestAlgorithm.SHA224, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384,
				DigestAlgorithm.SHA512, DigestAlgorithm.SHA3_224, DigestAlgorithm.SHA3_256, DigestAlgorithm.SHA3_384, DigestAlgorithm.SHA3_512);

		// List<DigestAlgorithm> mgf1SupportedAlgos = Arrays.asList(DigestAlgorithm.SHA1, DigestAlgorithm.SHA224,
		// DigestAlgorithm.SHA256, DigestAlgorithm.SHA384,
		// DigestAlgorithm.SHA512);

		List<Object[]> digests = new ArrayList<Object[]>();
		for (DigestAlgorithm digest1 : digestAlgos) {
			for (DigestAlgorithm digest2 : digestAlgos) {
				if (DigestAlgorithm.SHA1 == digest2) {
					// Due to
					// org.bouncycastle.cms.DefaultCMSSignatureEncryptionAlgorithmFinder.findEncryptionAlgorithm(AlgorithmIdentifier)
					if (digest1 == digest2) {
						digests.add(new Object[] { digest1, digest1, null });
						digests.add(new Object[] { digest1, digest1, MaskGenerationFunction.MGF1 });
					}
				} else {
					digests.add(new Object[] { digest1, digest2, null });
					digests.add(new Object[] { digest1, digest2, MaskGenerationFunction.MGF1 });
				}
			}
		}
		return digests;
	}

	public DSS1419CreationTest(DigestAlgorithm messageDigestAlgo, DigestAlgorithm digestAlgo, MaskGenerationFunction maskGenerationFunction) {
		this.messageDigestAlgo = messageDigestAlgo;
		this.digestAlgo = digestAlgo;
		this.maskGenerationFunction = maskGenerationFunction;
	}

	@Before
	public void init() throws Exception {
		documentToSign = new InMemoryDocument(HELLO_WORLD.getBytes(),
				"BC-CAdES-BpB-att-" + messageDigestAlgo.name() + "-" + digestAlgo.name() + "withRSA" + (maskGenerationFunction == null ? "" : "MGF1") + ".p7m");

		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.setReferenceDigestAlgorithm(messageDigestAlgo);
		signatureParameters.setDigestAlgorithm(digestAlgo);
		signatureParameters.setMaskGenerationFunction(maskGenerationFunction);

		service = new CAdESService(getCompleteCertificateVerifier());

	}

	@Override
	protected DocumentSignatureService<CAdESSignatureParameters> getService() {
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
