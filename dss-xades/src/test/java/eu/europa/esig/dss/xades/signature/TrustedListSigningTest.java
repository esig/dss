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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.parsers.DocumentBuilderFactory;

import org.junit.Assert;
import org.junit.Before;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.signature.AbstractTestDocumentSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.DSSReference;
import eu.europa.esig.dss.xades.DSSTransform;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class TrustedListSigningTest extends AbstractTestDocumentSignatureService {

	private DocumentSignatureService<XAdESSignatureParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	private MockPrivateKeyEntry privateKeyEntry;

	@Before
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		CertificateService certificateService = new CertificateService();
		privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		service = new XAdESService(certificateVerifier);

		final List<DSSReference> references = new ArrayList<DSSReference>();

		DSSReference dssReference = new DSSReference();
		dssReference.setId("xml_ref_id");
		dssReference.setUri("");
		dssReference.setContents(documentToSign);
		dssReference.setDigestMethodAlgorithm(signatureParameters.getDigestAlgorithm());

		final List<DSSTransform> transforms = new ArrayList<DSSTransform>();

		DSSTransform dssTransform = new DSSTransform();
		dssTransform.setAlgorithm(CanonicalizationMethod.ENVELOPED);
		transforms.add(dssTransform);

		dssTransform = new DSSTransform();
		dssTransform.setAlgorithm(CanonicalizationMethod.EXCLUSIVE);
		transforms.add(dssTransform);

		dssReference.setTransforms(transforms);
		references.add(dssReference);

		signatureParameters.setReferences(references);

	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(byteArray));

			NodeList taglist = doc.getDocumentElement().getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
			Assert.assertEquals(1, taglist.getLength());

			NodeList refList = ((Element) taglist.item(0)).getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Reference");
			Assert.assertEquals(2, refList.getLength());

			NodeList transormfList = ((Element) refList.item(0)).getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Transform");
			Assert.assertEquals(2, transormfList.getLength());

			Assert.assertEquals("http://www.w3.org/2000/09/xmldsig#enveloped-signature", ((Element) transormfList.item(0)).getAttribute("Algorithm"));

		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail();
		}
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected MimeType getExpectedMime() {
		return MimeType.XML;
	}

	@Override
	protected boolean isBaselineT() {
		return false;
	}

	@Override
	protected boolean isBaselineLTA() {
		return false;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected MockPrivateKeyEntry getPrivateKeyEntry() {
		return privateKeyEntry;
	}

}
