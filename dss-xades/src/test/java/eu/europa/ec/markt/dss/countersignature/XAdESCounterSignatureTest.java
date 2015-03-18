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
package eu.europa.ec.markt.dss.countersignature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.mock.MockPrivateKeyEntry;
import eu.europa.ec.markt.dss.mock.MockSignatureTokenConnection;
import eu.europa.ec.markt.dss.parameter.XAdESSignatureParameters;
import eu.europa.ec.markt.dss.service.CertificateService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.xades.XAdESService;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeValue;
import eu.europa.ec.markt.dss.validation102853.xades.XPathQueryHolder;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;

public class XAdESCounterSignatureTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(XAdESCounterSignatureTest.class);

	@Test
	public void test() throws Exception {
		CertificateService certificateService = new CertificateService();
		DSSPrivateKeyEntry entryUserA = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA1);
		MockPrivateKeyEntry entryUserB = (MockPrivateKeyEntry) certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		DSSDocument document = new FileDocument(new File("src/test/resources/sample.xml"));

		// Sign
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(entryUserA.getCertificate());
		signatureParameters.setCertificateChain(entryUserA.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(certificateVerifier);

		byte[] dataToSign = service.getDataToSign(document, signatureParameters);
		byte[] signatureValue = sign(signatureParameters.getSignatureAlgorithm(), entryUserA.getPrivateKey(), dataToSign);
		DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);

		// Countersign
		Document documentDom = DSSXMLUtils.buildDOM(signedDocument);
		XPathQueryHolder xPathQueryHolder = new XPathQueryHolder();
		Node node = DSSXMLUtils.getNode(documentDom, xPathQueryHolder.XPATH__SIGNATURE);
		assertNotNull(node);
		NamedNodeMap attributes = node.getAttributes();
		Node attributeId = attributes.getNamedItem("Id");
		assertNotNull(attributeId);

		XAdESSignatureParameters countersigningParameters = new XAdESSignatureParameters();
		countersigningParameters.setPrivateKeyEntry(entryUserB);
		countersigningParameters.setSigningToken(new MockSignatureTokenConnection());
		countersigningParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		countersigningParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		countersigningParameters.setToCounterSignSignatureId(attributeId.getNodeValue());

		DSSDocument counterSignDocument = service.counterSignDocument(signedDocument, countersigningParameters);
		assertNotNull(counterSignDocument);

		if (LOGGER.isDebugEnabled()) {
			try {
				byte[] byteArray = IOUtils.toByteArray(counterSignDocument.openStream());
				LOGGER.debug(new String(byteArray));
			} catch (Exception e) {
				LOGGER.error("Cannot display file content", e);
			}
		}

		// Validate
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(counterSignDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		List<XmlDom> signatures = diagnosticData.getElements("/DiagnosticData/Signature");
		assertEquals(2, signatures.size());

		boolean foundCounterSignature = false;
		for (XmlDom xmlDom : signatures) {
			String type = xmlDom.getAttribute("Type");
			if (AttributeValue.COUNTERSIGNATURE.equals(type)) {
				foundCounterSignature = true;
			}
			assertTrue(diagnosticData.isBLevelTechnicallyValid(xmlDom.getAttribute("Id")));
		}
		assertTrue(foundCounterSignature);
	}

	private byte[] sign(SignatureAlgorithm algo, PrivateKey privateKey, byte[] bytesToSign) throws GeneralSecurityException {
		final Signature signature = Signature.getInstance(algo.getJCEId());
		signature.initSign(privateKey);
		signature.update(bytesToSign);
		final byte[] signatureValue = signature.sign();
		return signatureValue;
	}

}
