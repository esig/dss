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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESManifestFromDigestDocumentsLevelBTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {

		List<DSSDocument> documents = Arrays.asList(new FileDocument("src/test/resources/sample.png"),
				new FileDocument("src/test/resources/sample.txt"), new FileDocument("src/test/resources/sample.xml"));

		List<DSSDocument> digestDocuments = new ArrayList<>();
		for (DSSDocument dssDocument : documents) {
			DigestDocument digestDocument = new DigestDocument(DigestAlgorithm.SHA512, dssDocument.getDigestValue(DigestAlgorithm.SHA512));
			digestDocument.setName(dssDocument.getName());
			digestDocuments.add(digestDocument);
		}

		ManifestBuilder builder = new ManifestBuilder(DigestAlgorithm.SHA512, digestDocuments);

		documentToSign = builder.build();

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setManifestSignature(true);

		service = new XAdESService(getOfflineCertificateVerifier());
	}

	@Override
	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		super.verifyDiagnosticData(diagnosticData);

		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

		int nbManifestEntries = 0;
		boolean foundManifest = false;
		boolean foundSignedProperties = false;
		List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
		for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
			switch (xmlDigestMatcher.getType()) {
			case MANIFEST:
				foundManifest = true;
				break;
			case MANIFEST_ENTRY:
				nbManifestEntries++;
				break;
			case SIGNED_PROPERTIES:
				foundSignedProperties = true;
				break;
			default:
				break;
			}
		}

		assertTrue(foundManifest);
		assertEquals(0, nbManifestEntries);
		assertTrue(foundSignedProperties);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
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

}
