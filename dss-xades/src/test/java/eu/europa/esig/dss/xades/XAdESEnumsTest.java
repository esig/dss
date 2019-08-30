package eu.europa.esig.dss.xades;

import static org.junit.Assert.assertTrue;

import java.io.InputStream;

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.xades.XAdESUtils;

public class XAdESEnumsTest {

//	private static final Logger LOG = LoggerFactory.getLogger(XAdESEnumsTest.class);

	@Test
	public void getAllEments() throws Exception {

		try (InputStream is = XAdESUtils.class.getResourceAsStream(XAdESUtils.XADES_SCHEMA_LOCATION_EN_319_132)) {
			Document dom = DomUtils.buildDOM(is);

			DomUtils.registerNamespace("xsd", "http://www.w3.org/2001/XMLSchema");

			NodeList nodeList = DomUtils.getNodeList(dom, "//xsd:element");
			assertTrue(nodeList.getLength() > 0);

			for (int i = 0; i < nodeList.getLength(); i++) {
				Node item = nodeList.item(i);
				if (item instanceof Element) {
					Element element = (Element) item;
					String tagName = element.getAttribute("name");
					if (tagName != null && !tagName.isEmpty()) {
//						LOG.info(tagName);

						boolean found = false;
						for (XAdES132Element xadesElement : XAdES132Element.values()) {
							if (tagName.equals(xadesElement.getTagName())) {
								found = true;
								break;
							}
						}
						assertTrue("TagName [" + tagName + "] not found", found);
					}
				}
			}
		}
	}

	@Test
	public void getAllAttributes() throws Exception {

		try (InputStream is = XAdESUtils.class.getResourceAsStream(XAdESUtils.XADES_SCHEMA_LOCATION_EN_319_132)) {
			Document dom = DomUtils.buildDOM(is);
			DomUtils.registerNamespace("xsd", "http://www.w3.org/2001/XMLSchema");

			NodeList nodeList = DomUtils.getNodeList(dom, "//xsd:attribute");
			assertTrue(nodeList.getLength() > 0);

			for (int i = 0; i < nodeList.getLength(); i++) {
				Node item = nodeList.item(i);
				if (item instanceof Element) {
					Element element = (Element) item;
					String attributeName = element.getAttribute("name");
					if (attributeName != null && !attributeName.isEmpty()) {
//						LOG.info(attributeName);

						boolean found = false;
						for (XAdESAttribute xadesAttribute : XAdESAttribute.values()) {
							if (attributeName.equals(xadesAttribute.getAttributeName())) {
								found = true;
								break;
							}
						}
						assertTrue("Attribute name [" + attributeName + "] not found", found);
					}
				}
			}
		}

	}

}
