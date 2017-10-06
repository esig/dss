package eu.europa.esig.dss.xades.validation;

import static javax.xml.crypto.dsig.XMLSignature.XMLNS;
import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.xades.XPathQueryHolder;
import eu.europa.esig.dss.xades.signature.XAdESBuilder;

public class XAdESOCSPSourceTest {

	@Test
	public void test1() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/BE_ECON/Signature-X-BE_ECON-3.xml");

		Document documentDom = DomUtils.buildDOM(doc);
		NodeList signatureNodeList = documentDom.getElementsByTagNameNS(XMLNS, XAdESBuilder.SIGNATURE);
		assertEquals(1, signatureNodeList.getLength());

		Element element = (Element) signatureNodeList.item(0);

		XAdESOCSPSource ocspSource = new XAdESOCSPSource(element, new XPathQueryHolder());

		assertEquals(1, ocspSource.getEncapsulatedOCSPValues().size());
		assertEquals(0, ocspSource.getTimestampEncapsulatedOCSPValues().size());
	}

	@Test
	public void test2() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/HU_POL/Signature-X-HU_POL-3.xml");

		Document documentDom = DomUtils.buildDOM(doc);
		NodeList signatureNodeList = documentDom.getElementsByTagNameNS(XMLNS, XAdESBuilder.SIGNATURE);
		assertEquals(1, signatureNodeList.getLength());

		Element element = (Element) signatureNodeList.item(0);

		XAdESOCSPSource ocspSource = new XAdESOCSPSource(element, new XPathQueryHolder());

		assertEquals(2, ocspSource.getEncapsulatedOCSPValues().size());
		assertEquals(2, ocspSource.getTimestampEncapsulatedOCSPValues().size());
	}

	@Test
	public void test3() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/CY/Signature-X-CY-1.xml");

		Document documentDom = DomUtils.buildDOM(doc);
		NodeList signatureNodeList = documentDom.getElementsByTagNameNS(XMLNS, XAdESBuilder.SIGNATURE);
		assertEquals(1, signatureNodeList.getLength());

		Element element = (Element) signatureNodeList.item(0);

		XAdESOCSPSource ocspSource = new XAdESOCSPSource(element, new XPathQueryHolder());

		assertEquals(0, ocspSource.getEncapsulatedOCSPValues().size());
		assertEquals(0, ocspSource.getTimestampEncapsulatedOCSPValues().size());
	}

}
