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

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.apache.xml.security.c14n.Canonicalizer;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;

@Tag("slow")
class XAdESReferenceCanonicalizationTest extends AbstractXAdESTestSignature {
	
	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	private static Stream<Arguments> data() {
		Object[] canonicalizations = { Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS, Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS,
				Canonicalizer.ALGO_ID_C14N11_WITH_COMMENTS, Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS, Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS };
		Object[] packagings = { SignaturePackaging.ENVELOPED, SignaturePackaging.ENVELOPING, 
				SignaturePackaging.DETACHED, SignaturePackaging.INTERNALLY_DETACHED };
		return combine(canonicalizations, packagings);
	}

	static Stream<Arguments> combine(Object[] canonicalizations, Object[] packagings) {
		List<Arguments> args = new ArrayList<>();
		for (int i = 0; i < canonicalizations.length; i++) {
			for (int j = 0; j < packagings.length; j++) {
				args.add(Arguments.of(canonicalizations[i], packagings[j]));
			}
		}
		return args.stream();
	}

	@ParameterizedTest(name = "Canonicalization {index} : {0} - {1}")
	@MethodSource("data")
	void test(String canonicalization, SignaturePackaging packaging) {
		documentToSign = new FileDocument(new File("src/test/resources/sample-c14n.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(packaging);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		
		DSSReference dssReference = new DSSReference();
		dssReference.setContents(documentToSign);
		dssReference.setId("Canonicalization-Ref-Test");
		dssReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
		
		List<DSSTransform> dssTransforms = new ArrayList<>();
		if (SignaturePackaging.ENVELOPING.equals(packaging)) {
			dssReference.setType("http://www.w3.org/2000/09/xmldsig#Object");
			dssReference.setUri("#Ref-1");
			signatureParameters.setEmbedXML(true);
		} else if (SignaturePackaging.ENVELOPED.equals(packaging)) {
			dssTransforms.add(new EnvelopedSignatureTransform());
			dssReference.setUri("");
		} else if (SignaturePackaging.DETACHED.equals(packaging)) {
			dssReference.setUri(documentToSign.getName());
		} else if (SignaturePackaging.INTERNALLY_DETACHED.equals(packaging)) {
			dssReference.setUri("#ROOT");
		}
		dssTransforms.add(new CanonicalizationTransform(canonicalization));
		
		dssReference.setTransforms(dssTransforms);
		signatureParameters.setReferences(Arrays.asList(dssReference));

		service = new XAdESService(getOfflineCertificateVerifier());

		super.signAndVerify();
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
