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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.apache.xml.security.c14n.Canonicalizer;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Tag("slow")
class XAdESTimestampCanonicalizationTest extends AbstractXAdESTestSignature {
	
	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	private static Stream<Arguments> data() {
		Object[] canonicalizations = { Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS, Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS,
				Canonicalizer.ALGO_ID_C14N11_WITH_COMMENTS, Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS, Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS };
		Object[] packagings = { SignaturePackaging.ENVELOPED, SignaturePackaging.ENVELOPING, 
				SignaturePackaging.DETACHED, SignaturePackaging.INTERNALLY_DETACHED };
		Object[] levels = { SignatureLevel.XAdES_BASELINE_LTA, SignatureLevel.XAdES_A };
		return combine(canonicalizations, packagings, levels);
	}

	static Stream<Arguments> combine(Object[] canonicalizations, Object[] packagings, Object[] levels) {
		List<Arguments> args = new ArrayList<>();
		for (int i = 0; i < canonicalizations.length; i++) {
			for (int j = 0; j < canonicalizations.length; j++) {
				for (int k = 0; k < packagings.length; k++) {
					for (int m = 0; m < levels.length; m++) {
						args.add(Arguments.of(canonicalizations[i], canonicalizations[j], packagings[k], levels[m]));
					}
				}
			}
		}
		return args.stream();
	}

	@ParameterizedTest(name = "Canonicalization {index} : {0} - {1} - {2} - {3}")
	@MethodSource("data")
	void test(String contentTstC14N, String otherTstC14N, SignaturePackaging packaging, SignatureLevel level) {
		documentToSign = new FileDocument(new File("src/test/resources/sample-c14n.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(packaging);
		signatureParameters.setSignatureLevel(level);
		signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		signatureParameters.setContentTimestampParameters(new XAdESTimestampParameters(DigestAlgorithm.SHA256, contentTstC14N));
		signatureParameters.setSignatureTimestampParameters(new XAdESTimestampParameters(DigestAlgorithm.SHA256, otherTstC14N));
		signatureParameters.setArchiveTimestampParameters(new XAdESTimestampParameters(DigestAlgorithm.SHA256, otherTstC14N));

		service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		
		TimestampToken contentTimestamp = service.getContentTimestamp(documentToSign, signatureParameters);
		signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp));

		super.signAndVerify();
	}

	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertEquals(signatureParameters.getSignatureLevel(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		if (SignatureLevel.XAdES_A.equals(signatureParameters.getSignatureLevel())) {
			// skip (revocation data can be updated with respect to an incorporated reference)
		} else {
			super.checkOrphanTokens(diagnosticData);
		}
	}

	@Override
	public void signAndVerify() {
		// skip global test
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		return Arrays.asList(documentToSign);
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
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

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}