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
package eu.europa.esig.dss.xades.requirements;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;

public abstract class AbstractRequirementChecks extends PKIFactoryAccess {

	private static DocumentBuilderFactory dbf;
	private static XPath xpath;

	protected Document document;

	@BeforeClass
	public static void initClass() {
		dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);

		XPathFactory f = XPathFactory.newInstance();
		xpath = f.newXPath();
		xpath.setNamespaceContext(new XAdESNamespaceContext());
	}

	@Before
	public void init() throws Exception {
		DSSDocument signedDocument = getSignedDocument();
		signedDocument.save("target/requirement-check.xml");

		DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
		document = documentBuilder.parse(signedDocument.openStream());
	}

	protected abstract DSSDocument getSignedDocument() throws Exception;

	/**
	 * ds:KeyInfo/X509Data/X509Certificate shall be present in B/T/LT/LTA
	 */
	@Test
	public void checkX509CertificatePresent() throws XPathExpressionException {
		XPathExpression exp = xpath.compile("//ds:KeyInfo/ds:X509Data/ds:X509Certificate");
		NodeList nodeList = (NodeList) exp.evaluate(document, XPathConstants.NODESET);
		assertNotNull(nodeList);
		int length = nodeList.getLength();
		assertTrue(length > 0);

		for (int i = 0; i < length; i++) {
			Node node = nodeList.item(i);
			String certificateBase64 = node.getTextContent();
			byte[] decodeCertificate = Utils.fromBase64(certificateBase64);
			CertificateToken certificateToken = DSSUtils.loadCertificate(decodeCertificate);
			assertNotNull(certificateToken);
		}
	}

	/**
	 * ds:SignedInfo/ds:CanonicalizationMethod shall be present in B/T/LT/LTA
	 */
	@Test
	public void checkSignedInfoCanonicalizationMethodPresent() throws XPathExpressionException {
		XPathExpression exp = xpath.compile("//ds:SignedInfo/ds:CanonicalizationMethod");
		Node node = (Node) exp.evaluate(document, XPathConstants.NODE);
		assertNotNull(node);
		NamedNodeMap attributes = node.getAttributes();
		Node algoNode = attributes.getNamedItem("Algorithm");
		assertTrue(Utils.isStringNotEmpty(algoNode.getTextContent()));
	}

	/**
	 * ds:Reference shall be present in B/T/LT/LTA
	 */
	@Test
	public void checkReferencesPresent() throws XPathExpressionException {
		XPathExpression exp = xpath.compile("//ds:Reference");
		NodeList nodeList = (NodeList) exp.evaluate(document, XPathConstants.NODESET);
		assertNotNull(nodeList);
		int length = nodeList.getLength();
		assertTrue(length >= 2);
	}

	/**
	 * SigningTime shall be present in B/T/LT/LTA
	 */
	@Test
	public void checkSigningTimePresent() throws XPathExpressionException {
		XPathExpression exp = xpath.compile("//xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningTime");
		Node node = (Node) exp.evaluate(document, XPathConstants.NODE);
		assertNotNull(node);
	}

	/**
	 * SigingCertificate shall be present in B/T/LT/LTA
	 */
	@Test
	public void checkSigningCertificatePresent() throws XPathExpressionException {
		XPathExpression exp = xpath.compile("//xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificateV2");
		Node node = (Node) exp.evaluate(document, XPathConstants.NODE);
		assertNotNull(node);
	}

	/**
	 * DataObjectFormat with attribute ObjectReference shall be present in B/T/LT/LTA
	 */
	@Test
	public void checkDataObjectFormatPresent() throws XPathExpressionException {
		XPathExpression exp = xpath.compile("//xades:SignedProperties/xades:SignedDataObjectProperties/xades:DataObjectFormat");
		Node node = (Node) exp.evaluate(document, XPathConstants.NODE);
		assertNotNull(node);

		NamedNodeMap attributes = node.getAttributes();
		Node objectReferenceAttribute = attributes.getNamedItem("ObjectReference");
		assertTrue(Utils.isStringNotEmpty(objectReferenceAttribute.getTextContent()));
	}

	/**
	 * DataObjectFormat/MimeType shall be present in B/T/LT/LTA
	 */
	@Test
	public void checkDataObjectFormatMimeTypePresent() throws XPathExpressionException {
		XPathExpression exp = xpath.compile("//xades:SignedProperties/xades:SignedDataObjectProperties/xades:DataObjectFormat/xades:MimeType");
		Node node = (Node) exp.evaluate(document, XPathConstants.NODE);
		assertNotNull(node);
		assertTrue(Utils.isStringNotEmpty(node.getTextContent()));
	}

	/**
	 * SignatureTimeStamp shall be present in T/LT/LTA
	 */
	@Test
	public void checkSignatureTimeStampPresent() throws XPathExpressionException {
		XPathExpression exp = xpath.compile("//xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:SignatureTimeStamp");
		Node node = (Node) exp.evaluate(document, XPathConstants.NODE);
		assertNotNull(node);
	}

	/**
	 * ArchiveTimeStamp shall be present in LTA
	 */
	@Test
	public void checkArchiveTimeStampPresent() throws XPathExpressionException {
		XPathExpression exp = xpath.compile("//xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:ArchiveTimeStamp");
		Node node = (Node) exp.evaluate(document, XPathConstants.NODE);
		assertNotNull(node);
	}

}
