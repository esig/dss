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

import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.TrustedListSignatureParametersBuilder;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.io.ByteArrayInputStream;
import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class TrustedListSignatureParametersBuilderTest extends AbstractXAdESTestSignature {
	
	private static final String REFERENCE_ID = "dss-tl-id-1";
	private static final DigestAlgorithm REFERENCE_DIGEST_ALGORITHM = DigestAlgorithm.SHA512;

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/eu-lotl-no-sig.xml"));
		service = new XAdESService(getOfflineCertificateVerifier());
		
		signatureParameters = getSignatureParametersBuilder().build();
	}

	protected TrustedListSignatureParametersBuilder getSignatureParametersBuilder() {
		return new TrustedListSignatureParametersBuilder(getSigningCert(), documentToSign)
				.setReferenceId(REFERENCE_ID)
				.setReferenceDigestAlgorithm(REFERENCE_DIGEST_ALGORITHM);
	}
	
	@Override
	protected String getCanonicalizationMethod() {
		return CanonicalizationMethod.EXCLUSIVE;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);

		try {
			Document doc = DomUtils.getSecureDocumentBuilderFactory()
					.newDocumentBuilder().parse(new ByteArrayInputStream(byteArray));

			NodeList signlist = doc.getDocumentElement().getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
			assertEquals(1, signlist.getLength());

			NodeList refList = ((Element) signlist.item(0)).getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Reference");
			assertEquals(2, refList.getLength());
			
			String idAttr = ((Element) refList.item(0)).getAttribute("Id");
			assertEquals(REFERENCE_ID, idAttr);

			NodeList digestMethodList = ((Element) refList.item(0)).getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "DigestMethod");
			assertEquals(1, digestMethodList.getLength());
			
			assertEquals(REFERENCE_DIGEST_ALGORITHM.getUri(), ((Element) digestMethodList.item(0)).getAttribute("Algorithm"));

			NodeList transormfList = ((Element) refList.item(0)).getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Transform");
			assertEquals(2, transormfList.getLength());

			assertEquals("http://www.w3.org/2000/09/xmldsig#enveloped-signature", ((Element) transormfList.item(0)).getAttribute("Algorithm"));

			assertEquals("http://www.w3.org/2001/10/xml-exc-c14n#", ((Element) transormfList.item(1)).getAttribute("Algorithm"));

			NodeList keyInfoList = ((Element) signlist.item(0)).getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "KeyInfo");
			assertEquals(1, keyInfoList.getLength());

			NodeList x509DataList = ((Element) keyInfoList.item(0)).getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509Data");
			assertEquals(1, x509DataList.getLength());

			NodeList x509CertificateList = ((Element) x509DataList.item(0)).getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509Certificate");
			assertEquals(1, x509CertificateList.getLength());
			
			NodeList objectlist = ((Element) signlist.item(0)).getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Object");
			assertEquals(1, objectlist.getLength());
			
			NodeList qualProplist = ((Element) objectlist.item(0)).getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "QualifyingProperties");
			assertEquals(1, qualProplist.getLength());
			
			NodeList signProplist = ((Element) qualProplist.item(0)).getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "SignedProperties");
			assertEquals(1, signProplist.getLength());
			
			NodeList signSigProplist = ((Element) qualProplist.item(0)).getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "SignedSignatureProperties");
			assertEquals(1, signSigProplist.getLength());
			
			NodeList signCertlist = ((Element) qualProplist.item(0)).getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "SigningCertificate");
			assertEquals(1, signCertlist.getLength());
			
			NodeList signCertV2list = ((Element) qualProplist.item(0)).getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "SigningCertificateV2");
			assertEquals(0, signCertV2list.getLength());

		} catch (Exception e) {
			fail(e);
		}
	}
	
	@Override
	protected void checkMessageDigestAlgorithm(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		boolean referenceFound = false;
		for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
			if (DigestMatcherType.REFERENCE.equals(digestMatcher.getType())) {
				assertEquals(REFERENCE_DIGEST_ALGORITHM, digestMatcher.getDigestMethod());
				referenceFound = true;
			}
		}
		assertTrue(referenceFound);
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
