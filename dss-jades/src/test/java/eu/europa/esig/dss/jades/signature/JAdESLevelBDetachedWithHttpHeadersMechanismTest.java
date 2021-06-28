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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.jades.HTTPHeader;
import eu.europa.esig.dss.jades.HTTPHeaderDigest;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JAdESLevelBDetachedWithHttpHeadersMechanismTest extends AbstractJAdESMultipleDocumentSignatureTest {

	private MultipleDocumentsSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
	private JAdESSignatureParameters signatureParameters;
	private DSSDocument originalDocument;
	private List<DSSDocument> documentsToSign;
	private Date signingDate;

	@BeforeEach
	public void init() throws Exception {
		JAdESService jadesService = new JAdESService(getCompleteCertificateVerifier());
		jadesService.setTspSource(getGoodTsa());
		service = jadesService;
		
		signingDate = new Date();
		
		originalDocument = new FileDocument("src/test/resources/sample.json");
		
		documentsToSign = new ArrayList<>();
		documentsToSign.add(new HTTPHeader("content-type", "application/json"));
		documentsToSign.add(new HTTPHeader("x-example", "HTTP Headers Example"));
		documentsToSign.add(new HTTPHeader("x-example", "Duplicated Header"));     
		
		// build "Digest" header manually
        String digest = originalDocument.getDigest(DigestAlgorithm.SHA1);
        documentsToSign.add(new HTTPHeader("Digest", "SHA="+digest));

		signatureParameters = new JAdESSignatureParameters();

		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		
		signatureParameters.setSigDMechanism(SigDMechanism.HTTP_HEADERS);
	}

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		// change order
		List<DSSDocument> detachedContents = new ArrayList<>();

		detachedContents.add(new HTTPHeader("x-example", "HTTP Headers Example"));
		detachedContents.add(new HTTPHeaderDigest(originalDocument, DigestAlgorithm.SHA1));
		detachedContents.add(new HTTPHeader("content-type", "application/json"));
		detachedContents.add(new HTTPHeader("x-example", "Duplicated Header"));
		
		return detachedContents;
	}
	
	@Override
	protected DSSDocument sign() {
		Exception exception = assertThrows(IllegalArgumentException.class, () -> super.sign());
		assertEquals("'http://uri.etsi.org/19182/HttpHeaders' SigD Mechanism can be used only with non-base64url encoded payload! "
				+ "Set JAdESSignatureParameters.setBase64UrlEncodedPayload(true).", exception.getMessage());

		signatureParameters.setBase64UrlEncodedPayload(false);
		DSSDocument signedDocument = super.sign();
		assertNotNull(signedDocument);

		return signedDocument;
	}
	
	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		super.checkSignatureScopes(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		assertEquals(2, signatureScopes.size());
		
		boolean payloadSignatureScopeFound = false;
		boolean httpHeaderDigestSignatureScopeFound = false;
		
		for (XmlSignatureScope xmlSignatureScope : signatureScopes) {
			if ("HttpHeaders payload".equals(xmlSignatureScope.getName())) {
				assertEquals("Payload value digest", xmlSignatureScope.getDescription());
				payloadSignatureScopeFound = true;
			} else if (originalDocument.getName().equals(xmlSignatureScope.getName())) {
				assertEquals("Message body value digest", xmlSignatureScope.getDescription());
				httpHeaderDigestSignatureScopeFound = true;
			}
			assertEquals(SignatureScopeType.FULL, xmlSignatureScope.getScope());
			assertNotNull(xmlSignatureScope.getSignerData());
			assertTrue(Utils.isCollectionEmpty(xmlSignatureScope.getTransformations()));
		}
		
		assertTrue(payloadSignatureScopeFound);
		assertTrue(httpHeaderDigestSignatureScopeFound);
	}

	@Override
	protected MultipleDocumentsSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	@Override
	protected List<DSSDocument> getDocumentsToSign() {
		return documentsToSign;
	}

}
