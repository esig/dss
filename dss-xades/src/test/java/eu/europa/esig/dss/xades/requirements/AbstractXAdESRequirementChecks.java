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
package eu.europa.esig.dss.xades.requirements;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.signature.AbstractXAdESTestSignature;
import eu.europa.esig.dss.xml.common.definition.DSSElement;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.common.xpath.XPathQuery;
import eu.europa.esig.dss.xml.common.xpath.XPathQueryBuilder;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.xpath.XPathUtils;
import org.junit.jupiter.api.BeforeAll;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class AbstractXAdESRequirementChecks extends AbstractXAdESTestSignature {

	protected Document document;

	@BeforeAll
	public static void initClass() {
		XPathUtils.registerNamespace(new DSSNamespace("http://uri.etsi.org/01903/v1.3.2#", "xades"));
		XPathUtils.registerNamespace(new DSSNamespace("http://uri.etsi.org/01903/v1.4.1#", "xades141"));
		XPathUtils.registerNamespace(new DSSNamespace("http://www.w3.org/2000/09/xmldsig#", "ds"));
	}
	
	@Override
	protected void onDocumentSigned(byte[] byteArray)  {
		super.onDocumentSigned(byteArray);
		
		try (ByteArrayInputStream bais = new ByteArrayInputStream(byteArray)) {
			DocumentBuilder documentBuilder = DomUtils.getSecureDocumentBuilderFactory().newDocumentBuilder();
			document = documentBuilder.parse(bais);
			
			checkX509CertificatePresent();
			checkSignedInfoCanonicalizationMethodPresent();
			checkReferencesPresent();
			checkSigningTimePresent();
			checkSigningCertificatePresent();
			checkDataObjectFormatPresent();
			checkDataObjectFormatMimeTypePresent();
			checkUnsignedProperties();
			
		} catch (Exception e) {
			fail(e);
		}
	}

	/**
	 * ds:KeyInfo/X509Data/X509Certificate shall be present in B/T/LT/LTA
	 */
	protected void checkX509CertificatePresent() {
		XPathQuery exp = toXPathQuery("ds:KeyInfo", "ds:X509Data", "ds:X509Certificate");
		NodeList nodeList = XPathUtils.getNodeList(document, exp);
		assertNotNull(nodeList);
		int length = nodeList.getLength();
		assertTrue(length > 0);

		for (int i = 0; i < length; i++) {
			Node node = nodeList.item(i);
			String certificateBase64 = node.getTextContent();
			assertNotNull(certificateBase64);
			assertTrue(Utils.isBase64Encoded(certificateBase64));
			byte[] decodeCertificate = Utils.fromBase64(certificateBase64);
			CertificateToken certificateToken = DSSUtils.loadCertificate(decodeCertificate);
			assertNotNull(certificateToken);
		}
	}

	/**
	 * ds:SignedInfo", "ds:CanonicalizationMethod shall be present in B/T/LT/LTA
	 */
	protected void checkSignedInfoCanonicalizationMethodPresent() {
		XPathQuery exp = toXPathQuery("ds:SignedInfo", "ds:CanonicalizationMethod");
		Node node = XPathUtils.getNode(document, exp);
		assertNotNull(node);
		NamedNodeMap attributes = node.getAttributes();
		Node algoNode = attributes.getNamedItem("Algorithm");
		assertTrue(Utils.isStringNotEmpty(algoNode.getTextContent()));
	}

	/**
	 * ds:Reference shall be present in B/T/LT/LTA
	 */
	protected void checkReferencesPresent() {
		XPathQuery exp = toXPathQuery("ds:Reference");
		NodeList nodeList = XPathUtils.getNodeList(document, exp);
		assertNotNull(nodeList);
		int length = nodeList.getLength();
		assertTrue(length >= 2);
	}

	/**
	 * SigningTime shall be present in B/T/LT/LTA
	 */
	protected void checkSigningTimePresent() {
		XPathQuery exp = toXPathQuery("xades:SignedProperties", "xades:SignedSignatureProperties", "xades:SigningTime");
		Node node = XPathUtils.getNode(document, exp);
		assertNotNull(node);
	}

	/**
	 * SigningCertificate shall be present in B/T/LT/LTA
	 */
	protected void checkSigningCertificatePresent() {
		XPathQuery exp = toXPathQuery("xades:SignedProperties", "xades:SignedSignatureProperties", "xades:SigningCertificateV2");
		Node node = XPathUtils.getNode(document, exp);
		assertNotNull(node);
	}

	/**
	 * DataObjectFormat with attribute ObjectReference shall be present in B/T/LT/LTA
	 */
	protected void checkDataObjectFormatPresent() {
		XPathQuery exp = toXPathQuery("xades:SignedProperties", "xades:SignedDataObjectProperties", "xades:DataObjectFormat");
		Node node = XPathUtils.getNode(document, exp);
		assertNotNull(node);

		NamedNodeMap attributes = node.getAttributes();
		Node objectReferenceAttribute = attributes.getNamedItem("ObjectReference");
		assertTrue(Utils.isStringNotEmpty(objectReferenceAttribute.getTextContent()));
	}

	/**
	 * DataObjectFormat/MimeType shall be present in B/T/LT/LTA
	 */
	protected void checkDataObjectFormatMimeTypePresent() {
		XPathQuery exp = toXPathQuery("xades:SignedProperties", "xades:SignedDataObjectProperties", "xades:DataObjectFormat", "xades:MimeType");
		Node node = XPathUtils.getNode(document, exp);
		assertNotNull(node);
		assertTrue(Utils.isStringNotEmpty(node.getTextContent()));
	}

	/**
	 * Checks UnsignedSignatureProperties present for T/LT/LTA levels
	 */
	protected abstract void checkUnsignedProperties();

	/**
	 * SignatureTimeStamp shall be present in T/LT/LTA
	 */
	protected void checkSignatureTimeStampPresent() {
		XPathQuery exp = toXPathQuery("xades:UnsignedProperties", "xades:UnsignedSignatureProperties", "xades:SignatureTimeStamp");
		Node node = XPathUtils.getNode(document, exp);
		assertNotNull(node);
	}

	/**
	 * CertificateValues shall be present in LT/LTA
	 *
	 * @return whether the CertificateValues element is present
	 */
	protected boolean checkCertificateValuesPresent() {
		XPathQuery exp = toXPathQuery("xades:UnsignedProperties", "xades:UnsignedSignatureProperties", "xades:CertificateValues");
		Node node = XPathUtils.getNode(document, exp);
		return node != null;
	}

	/**
	 * RevocationValues shall be present in LT/LTA
	 *
	 * @return whether the RevocationValues element is present
	 */
	protected boolean checkRevocationValuesPresent() {
		XPathQuery exp = toXPathQuery("xades:UnsignedProperties", "xades:UnsignedSignatureProperties", "xades:RevocationValues");
		Node node = XPathUtils.getNode(document, exp);
		return node != null;
	}

	/**
	 * ArchiveTimeStamp shall be present in LTA
	 */
	protected void checkArchiveTimeStampPresent() {
		XPathQuery exp = toXPathQuery("xades:UnsignedProperties", "xades:UnsignedSignatureProperties", "xades141:ArchiveTimeStamp");
		Node node = XPathUtils.getNode(document, exp);
		assertNotNull(node);
	}

	/**
	 * TimeStampValidationData may be present in LT/LTA
	 *
	 * @return whether the TimeStampValidationData element is present
	 */
	protected boolean checkTimeStampValidationDataPresent() {
		XPathQuery exp = toXPathQuery("xades:UnsignedProperties", "xades:UnsignedSignatureProperties", "xades141:TimeStampValidationData");
		Node node = XPathUtils.getNode(document, exp);
		return node != null;
	}

	/**
	 * AnyValidationData may be present in LT/LTA
	 *
	 * @return whether the AnyValidationData element is present
	 */
	protected boolean checkAnyValidationDataPresent() {
		XPathQuery exp = toXPathQuery("xades:UnsignedProperties", "xades:UnsignedSignatureProperties", "xades141:AnyValidationData");
		Node node = XPathUtils.getNode(document, exp);
		return node != null;
	}

	/**
	 * CompleteCertificateRefsV2 shall be present in C/X/XL/A
	 */
	protected void checkCompleteCertificateRefsV2Present() {
		XPathQuery exp = toXPathQuery("xades:UnsignedProperties", "xades:UnsignedSignatureProperties", "xades141:CompleteCertificateRefsV2");
		Node node = XPathUtils.getNode(document, exp);
		assertNotNull(node);
	}

	/**
	 * CompleteRevocationRefs shall be present in C/X/XL/A
	 */
	protected void checkCompleteRevocationRefsPresent() {
		XPathQuery exp = toXPathQuery("xades:UnsignedProperties", "xades:UnsignedSignatureProperties", "xades:CompleteRevocationRefs");
		Node node = XPathUtils.getNode(document, exp);
		assertNotNull(node);
	}

	/**
	 * SigAndRefsTimeStampV2 shall be present in X/XL/A
	 */
	protected void checkSigAndRefsTimeStampV2Present() {
		XPathQuery exp = toXPathQuery("xades:UnsignedProperties", "xades:UnsignedSignatureProperties", "xades141:SigAndRefsTimeStampV2");
		Node node = XPathUtils.getNode(document, exp);
		assertNotNull(node);
	}

	protected XPathQuery toXPathQuery(String... elements) {
		final XPathQueryBuilder builder = XPathQueryBuilder.all();
		
		List<DSSElement> elementList = new ArrayList<>();
		for (String element : elements) {
			String[] parts = element.split(":", 2);
			String prefix = parts[0];
			String localName = parts[1];
			elementList.add(DSSElement.fromDefinition(localName, new DSSNamespace(XPathUtils.getNamespaceContextMap().getNamespaceURI(prefix), prefix)));
		}
		builder.elements(elementList.toArray(new DSSElement[0]));
		
		return builder.build();
	}

}
