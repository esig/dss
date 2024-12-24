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
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS920WithWrongDigestTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {

		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSigningCertificate(getSigningCert());

		service = new XAdESService(getOfflineCertificateVerifier());
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		List<DSSDocument> detachedContents = new ArrayList<>();
		DigestDocument digestDocument = new DigestDocument(DigestAlgorithm.SHA1, documentToSign.getDigestValue(DigestAlgorithm.SHA1));
		digestDocument.setName("sample.xml");
		detachedContents.add(digestDocument);
		return detachedContents;
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isDocHashOnly());
		assertFalse(signature.isHashOnly());
		
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertEquals(2, digestMatchers.size());
		boolean refToDigestDocumentCreated = false;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			if (DigestAlgorithm.SHA256.equals(digestMatcher.getDigestMethod()) &&
					Arrays.equals(documentToSign.getDigestValue(DigestAlgorithm.SHA256), digestMatcher.getDigestValue())) {
				refToDigestDocumentCreated = true;
				assertFalse(digestMatcher.isDataFound());
				assertFalse(digestMatcher.isDataIntact());
			}
		}
		assertTrue(refToDigestDocumentCreated);
	}
	
	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		super.checkSignatureScopes(diagnosticData);

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		XmlSignatureScope xmlSignatureScope = signatureScopes.get(0);

        assertArrayEquals(xmlSignatureScope.getSignerData().getDigestAlgoAndValue().getDigestValue(),
				documentToSign.getDigestValue(xmlSignatureScope.getSignerData().getDigestAlgoAndValue().getDigestMethod()));
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		List<SignerDataWrapper> originalSignerDocuments = diagnosticData.getOriginalSignerDocuments();
		assertEquals(1, originalSignerDocuments.size());
		SignerDataWrapper originalDoc = originalSignerDocuments.get(0);
		assertEquals(documentToSign.getName(), originalDoc.getReferencedName());
		assertNotNull(originalDoc.getId());
		assertNotNull(originalDoc.getDigestAlgoAndValue());
		assertEquals(DigestAlgorithm.SHA256, originalDoc.getDigestAlgoAndValue().getDigestMethod());
		assertArrayEquals(documentToSign.getDigestValue(DigestAlgorithm.SHA256),
				originalDoc.getDigestAlgoAndValue().getDigestValue());
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
