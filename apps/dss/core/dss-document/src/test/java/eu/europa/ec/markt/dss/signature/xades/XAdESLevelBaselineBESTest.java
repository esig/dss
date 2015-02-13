/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2011 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature.xades;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import javax.xml.crypto.Data;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.service.CertificateService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.report.Reports;

/**
 * @version $Revision$ - $Date$
 */
public class XAdESLevelBaselineBESTest {

	private static SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSA_SHA256;

	private static DSSDocument toBeSigned;

	private static DSSPrivateKeyEntry privateKeyEntry;

	private static Date signingDate;

	@BeforeClass
	public static void setUp() throws Exception {
		toBeSigned = new InMemoryDocument("<?xml version=\"1.0\"?><root><bonjour/></root>".getBytes());
		CertificateService certificateService = new CertificateService();
		privateKeyEntry = certificateService.generateCertificateChain(signatureAlgorithm);

		Calendar calendar = Calendar.getInstance();
		calendar.setTime(new Date());
		calendar.set(Calendar.MILLISECOND, 0); // XML doesn't use millisecond

		signingDate = calendar.getTime();
	}

	@Test
	public void testSign() throws Exception {

		CommonCertificateVerifier verifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(verifier);

		SignatureParameters params = new SignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(privateKeyEntry.getCertificate());
		params.bLevel().setSigningDate(signingDate);

		byte[] dataToSign = service.getDataToSign(toBeSigned, params);
		byte[] signatureValue = DSSUtils.encrypt(signatureAlgorithm.getJCEId(), privateKeyEntry.getPrivateKey(), dataToSign);
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		AdvancedSignature s = validator.getSignatures().get(0);
		assertEquals(signingDate, s.getSigningTime());

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void testSign2() throws Exception {

		CommonCertificateVerifier verifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(verifier);

		SignatureParameters params = new SignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(privateKeyEntry.getCertificate());
		params.bLevel().setSigningDate(signingDate);

		byte[] dataToSign = service.getDataToSign(toBeSigned, params);
		byte[] signatureValue = DSSUtils.encrypt(signatureAlgorithm.getJCEId(), privateKeyEntry.getPrivateKey(), dataToSign);
		DSSDocument doc = service.signDocument(toBeSigned, params, signatureValue);

		FileOutputStream output = new FileOutputStream("target/signed-xml-bes.xml");
		DSSUtils.copy(doc.openStream(), output);
		output.close();

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		DocumentBuilder db = dbf.newDocumentBuilder();
		Element rootElement = db.parse(doc.openStream()).getDocumentElement();
		DSSXMLUtils.recursiveIdBrowse(rootElement);

		NodeList signatureNodeList = rootElement.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		for (int j = 0; j < signatureNodeList.getLength(); j++) {
			Element signatureEl = (Element) signatureNodeList.item(j);

			DOMValidateContext valContext = new DOMValidateContext(KeySelector.singletonKeySelector(privateKeyEntry.getCertificate().getPublicKey()),
					signatureEl);
			XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
			XMLSignature signature = factory.unmarshalXMLSignature(valContext);
			boolean coreValidity = signature.validate(valContext);
			// System.out.println("Validation of signature");
			assertTrue(coreValidity);

		}

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(verifier);
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		AdvancedSignature advancedSignature = signatures.get(0);
		assertEquals(signingDate, advancedSignature.getSigningTime());
		assertEquals(privateKeyEntry.getCertificate(), advancedSignature.getSigningCertificateToken().getCertificate());
	}

	@Test
	public void testEnveloping() throws Exception {

		toBeSigned = new InMemoryDocument("<?xml version=\"1.0\"?><ds:rootElement xmlns:ds=\"http://test\"><ds:bonjour/></ds:rootElement>".getBytes());

		CommonCertificateVerifier verifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(verifier);

		SignatureParameters params = new SignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		params.setSigningCertificate(privateKeyEntry.getCertificate());
		params.bLevel().setSigningDate(signingDate);

		byte[] dataToSign = service.getDataToSign(toBeSigned, params);
		byte[] signatureValue = DSSUtils.encrypt(signatureAlgorithm.getJCEId(), privateKeyEntry.getPrivateKey(), dataToSign);
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

		System.out.println("**************");
		DSSUtils.copy(signedDocument.openStream(), System.out);
		System.out.println("**************");

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		DocumentBuilder db = dbf.newDocumentBuilder();
		org.w3c.dom.Document rootElement = db.parse(signedDocument.openStream());
		// DSSXMLUtils.recursiveIdBrowse(rootElement);

		NodeList signatureNodeList = rootElement.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		assertEquals(1, signatureNodeList.getLength());
		for (int j = 0; j < signatureNodeList.getLength(); j++) {
			Element signatureEl = (Element) signatureNodeList.item(j);

			DOMValidateContext valContext = new DOMValidateContext(KeySelector.singletonKeySelector(privateKeyEntry.getCertificate().getPublicKey()),
					signatureEl);
			XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
			XMLSignature signature = factory.unmarshalXMLSignature(valContext);
			DSSXMLUtils.recursiveIdBrowse(valContext, signatureEl);
			assertTrue(signature.validate(valContext));
			System.out.println(signature.validate(valContext));
		}

	}

	@Test
	public void testEnvelopingBinary() throws Exception {

		toBeSigned = new InMemoryDocument(new byte[] { 0, 1, 2, 3, 4, 5, 6 });

		CommonCertificateVerifier verifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(verifier);

		SignatureParameters params = new SignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		params.setSigningCertificate(privateKeyEntry.getCertificate());
		params.bLevel().setSigningDate(signingDate);

		byte[] dataToSign = service.getDataToSign(toBeSigned, params);
		byte[] signatureValue = DSSUtils.encrypt(signatureAlgorithm.getJCEId(), privateKeyEntry.getPrivateKey(), dataToSign);
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

		System.out.println("**************");
		DSSUtils.copy(signedDocument.openStream(), System.out);
		System.out.println("**************");

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		DocumentBuilder db = dbf.newDocumentBuilder();
		org.w3c.dom.Document root = db.parse(signedDocument.openStream());

		NodeList signatureNodeList = root.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		assertEquals(1, signatureNodeList.getLength());
		for (int j = 0; j < signatureNodeList.getLength(); j++) {
			Element signatureEl = (Element) signatureNodeList.item(j);

			DOMValidateContext valContext = new DOMValidateContext(KeySelector.singletonKeySelector(privateKeyEntry.getCertificate().getPublicKey()),
					signatureEl);
			XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
			XMLSignature signature = factory.unmarshalXMLSignature(valContext);
			DSSXMLUtils.recursiveIdBrowse(valContext, signatureEl);
			assertTrue(signature.validate(valContext));
		}

	}

	@Test
	public void testDetachedBinary() throws Exception {

		final InMemoryDocument inMemoryDocument = new InMemoryDocument(new byte[] { 0, 1, 2, 3, 4, 5, 6 });
		inMemoryDocument.setName("test_document.123");
		toBeSigned = inMemoryDocument;

		CommonCertificateVerifier verifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(verifier);

		SignatureParameters params = new SignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.DETACHED);
		params.setSigningCertificate(privateKeyEntry.getCertificate());
		params.bLevel().setSigningDate(signingDate);

		byte[] dataToSign = service.getDataToSign(toBeSigned, params);
		byte[] signatureValue = DSSUtils.encrypt(signatureAlgorithm.getJCEId(), privateKeyEntry.getPrivateKey(), dataToSign);
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

		System.out.println("**************");
		DSSUtils.copy(signedDocument.openStream(), System.out);
		System.out.println("**************");

		Document root = DSSXMLUtils.buildDOM(signedDocument.openStream());

		NodeList signatureNodeList = root.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		assertEquals(1, signatureNodeList.getLength());
		for (int j = 0; j < signatureNodeList.getLength(); j++) {

			Element signatureEl = (Element) signatureNodeList.item(j);
			final PublicKey publicKey = privateKeyEntry.getCertificate().getPublicKey();
			DOMValidateContext valContext = new DOMValidateContext(KeySelector.singletonKeySelector(publicKey), signatureEl);

			valContext.setURIDereferencer(new URIDereferencer() {

				@Override
				public Data dereference(URIReference uriReference, XMLCryptoContext context) throws URIReferenceException {

					if (uriReference.getURI().equals(toBeSigned.getName())) {
						final InputStream octetStream = toBeSigned.openStream();
						return new OctetStreamData(octetStream);
					} else {
						final XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());
						return fac.getURIDereferencer().dereference(uriReference, context);
					}
				}
			});

			XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());
			XMLSignature signature = factory.unmarshalXMLSignature(valContext);
			DSSXMLUtils.recursiveIdBrowse(valContext, signatureEl);
			assertTrue(signature.validate(valContext));
		}

	}

}
