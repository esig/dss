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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

@Tag("slow")
public class JAdESLevelBWithECDSATest extends AbstractJAdESTestSignature {

	private DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
	private JAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	private String signingAlias;

	private static Stream<Arguments> data() {
		List<Arguments> args = new ArrayList<>();

		for (JWSSerializationType jwsSerializationType : JWSSerializationType.values()) {
			for (DigestAlgorithm digestAlgo : DigestAlgorithm.values()) {
				SignatureAlgorithm sa = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.ECDSA, digestAlgo);
				if (sa != null && Utils.isStringNotBlank(sa.getJWAId())) {
					args.add(Arguments.of(jwsSerializationType, digestAlgo, getSigner(digestAlgo)));
				}
			}
		}

		return args.stream();
	}

	private static String getSigner(DigestAlgorithm digestAlgorithm) {
		switch (digestAlgorithm) {
			case SHA256:
				return ECDSA_USER;
			case SHA384:
				return ECDSA_384_USER;
			case SHA512:
				return ECDSA_521_USER;
			default:
				throw new UnsupportedOperationException(String.format(
						"DigestAlgorithm '%s' is not supported!", digestAlgorithm));
		}
	}

	@ParameterizedTest(name = "Combination {index} if type {0} and ECDSA with digest algorithm {1} and signer {2}")
	@MethodSource("data")
	public void init(JWSSerializationType jwsSerializationType, DigestAlgorithm digestAlgo, String signingAlias) {
		this.signingAlias = signingAlias;

		documentToSign = new FileDocument(new File("src/test/resources/sample.json"));

		signatureParameters = new JAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		signatureParameters.setJwsSerializationType(jwsSerializationType);
		signatureParameters.setDigestAlgorithm(digestAlgo);

		service = new JAdESService(getOfflineCertificateVerifier());

		super.signAndVerify();
	}

	@Override
	public void signAndVerify() {
	}

	@Override
	protected DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
		return service;
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
	protected String getSigningAlias() {
		return signingAlias;
	}

}