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
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESMultipleManifestLevelBTest extends AbstractXAdESMultipleDocumentsSignatureService {

	private MultipleDocumentsSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private List<DSSDocument> documentToSigns;

	private List<DSSDocument> detachedContents;

	@BeforeEach
	void init() throws Exception {

		detachedContents = new ArrayList<>();
		detachedContents.add(new FileDocument("src/test/resources/sample.png"));
		detachedContents.add(new FileDocument("src/test/resources/sample.txt"));
		detachedContents.add(new FileDocument("src/test/resources/sample.xml"));

		ManifestBuilder builder1 = new ManifestBuilder("manifest-sha512", DigestAlgorithm.SHA512, detachedContents);
		ManifestBuilder builder2 = new ManifestBuilder("manifest-sha256", DigestAlgorithm.SHA256, detachedContents);

		documentToSigns = Arrays.asList(builder1.build(), builder2.build());

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setManifestSignature(true);

		service = new XAdESService(getOfflineCertificateVerifier());
	}

	@Override
	protected void checkDigestMatchers(DiagnosticData diagnosticData) {
		super.checkDigestMatchers(diagnosticData);

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertEquals(9, digestMatchers.size());

		int manifestCounter = 0;
		int manifestEntryCounter = 0;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			assertTrue(digestMatcher.isDataFound());
			assertTrue(digestMatcher.isDataIntact());
			if (DigestMatcherType.MANIFEST.equals(digestMatcher.getType())) {
				++manifestCounter;
			} else if (DigestMatcherType.MANIFEST_ENTRY.equals(digestMatcher.getType())) {
				++manifestEntryCounter;
			}
		}
		assertEquals(2, manifestCounter);
		assertEquals(6, manifestEntryCounter);
	}

	@Override
	public List<DSSDocument> getDetachedContents() {
		return detachedContents;
	}

	@Override
	protected MultipleDocumentsSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected List<DSSDocument> getDocumentsToSign() {
		return documentToSigns;
	}

}
