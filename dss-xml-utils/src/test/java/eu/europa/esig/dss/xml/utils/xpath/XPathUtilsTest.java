package eu.europa.esig.dss.xml.utils.xpath;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.xml.common.definition.DSSAttribute;
import eu.europa.esig.dss.xml.common.definition.DSSElement;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.common.xpath.XPathQuery;
import eu.europa.esig.dss.xml.common.xpath.XPathQueryBuilder;
import eu.europa.esig.dss.xml.utils.DomUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XPathUtilsTest {

    private static final Document DOC = DomUtils.buildDOM("<a><b><d>Hello</d><e><e pos=\"nested\">Nested</e></e></b><c><d>Bye</d><d Id=\"world\">World</d></c></a>");
    private static final String XML_WITH_NAMESPACE = "<m:manifest xmlns:m=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\"><m:file-entry m:media-type=\"text/plain\" m:full-path=\"hello.txt\" /></m:manifest>";

    @Test
    void registerNamespaceTest() {
        Document document = DomUtils.buildDOM(XML_WITH_NAMESPACE);

        DSSNamespace manifestNamespace = new DSSNamespace("urn:oasis:names:tc:opendocument:xmlns:manifest:1.0", "m");
        final XPathQuery xPathQuery = XPathQueryBuilder.fromCurrentPosition()
                .element(DSSElement.fromDefinition("file-entry", manifestNamespace)).build();
        Exception exception = assertThrows(DSSException.class, () -> XPathUtils.getElement(document.getDocumentElement(), xPathQuery));
        assertTrue(exception.getMessage().contains("Unable to create an XPath expression"));

        XPathUtils.registerNamespace(manifestNamespace);

        Element fileEntry = XPathUtils.getElement(document.getDocumentElement(), xPathQuery);
        assertNotNull(fileEntry);

        exception = assertThrows(UnsupportedOperationException.class,
                () -> XPathUtils.registerNamespace(new DSSNamespace("http://some-uri.net", null)));
        assertEquals("The empty namespace cannot be registered!", exception.getMessage());

        exception = assertThrows(UnsupportedOperationException.class,
                () -> XPathUtils.registerNamespace(new DSSNamespace("http://some-uri.net", "")));
        assertEquals("The empty namespace cannot be registered!", exception.getMessage());

        exception = assertThrows(UnsupportedOperationException.class,
                () -> XPathUtils.registerNamespace(new DSSNamespace("http://some-uri.net", "xmlns")));
        assertEquals("The default namespace 'xmlns' cannot be registered!", exception.getMessage());

        assertTrue(XPathUtils.registerNamespace(new DSSNamespace("http://some-uri.net", "otherPrefix")));
    }

    @Test
    void getElementByIdTest() {
        assertNotNull(XPathUtils.getElementById(
                DomUtils.buildDOM("<el id=\"signedData\">Text</el>"), "signedData"));
        assertNotNull(XPathUtils.getElementById(
                DomUtils.buildDOM("<el Id=\"signedData\">Text</el>"), "signedData"));
        assertNotNull(XPathUtils.getElementById(
                DomUtils.buildDOM("<el ID=\"signedData\">Text</el>"), "signedData"));
        assertNotNull(XPathUtils.getElementById(
                DomUtils.buildDOM("<el xmlns:prefix=\"urn:prefix\" prefix:id=\"signedData\">Text</el>"), "signedData"));
        assertNull(XPathUtils.getElementById(
                DomUtils.buildDOM("<el id=\"signedData\">Text</el>"), "notSignedData"));
        assertNull(XPathUtils.getElementById(
                DomUtils.buildDOM("<el ids=\"signedData\">Text</el>"), "signedData"));
    }

    @Test
    public void positionTest() {
        XPathQuery query = XPathQueryBuilder.all().element(getElement("a")).build();
        assertEquals(1, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.all().element(getElement("b")).build();
        assertEquals(1, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.all().element(getElement("c")).build();
        assertEquals(1, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.all().element(getElement("d")).build();
        assertEquals(3, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.all().element(getElement("e")).build();
        assertEquals(2, XPathUtils.getNodeList(DOC, query).getLength());

        query = XPathQueryBuilder.allFromCurrentPosition().element(getElement("a")).build();
        assertEquals(1, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.allFromCurrentPosition().element(getElement("b")).build();
        assertEquals(1, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.allFromCurrentPosition().element(getElement("c")).build();
        assertEquals(1, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.allFromCurrentPosition().element(getElement("d")).build();
        assertEquals(3, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.allFromCurrentPosition().element(getElement("e")).build();
        assertEquals(2, XPathUtils.getNodeList(DOC, query).getLength());

        query = XPathQueryBuilder.fromCurrentPosition().element(getElement("a")).build();
        assertEquals(1, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.fromCurrentPosition().element(getElement("b")).build();
        assertEquals(0, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.fromCurrentPosition().element(getElement("c")).build();
        assertEquals(0, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.fromCurrentPosition().element(getElement("d")).build();
        assertEquals(0, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.fromCurrentPosition().element(getElement("e")).build();
        assertEquals(0, XPathUtils.getNodeList(DOC, query).getLength());

        Node bElement = DOC.getDocumentElement().getFirstChild();

        query = XPathQueryBuilder.all().element(getElement("a")).build();
        assertEquals(1, XPathUtils.getNodeList(bElement, query).getLength());
        query = XPathQueryBuilder.all().element(getElement("b")).build();
        assertEquals(1, XPathUtils.getNodeList(bElement, query).getLength());
        query = XPathQueryBuilder.all().element(getElement("c")).build();
        assertEquals(1, XPathUtils.getNodeList(bElement, query).getLength());
        query = XPathQueryBuilder.all().element(getElement("d")).build();
        assertEquals(3, XPathUtils.getNodeList(bElement, query).getLength());
        query = XPathQueryBuilder.all().element(getElement("e")).build();
        assertEquals(2, XPathUtils.getNodeList(bElement, query).getLength());

        query = XPathQueryBuilder.allFromCurrentPosition().element(getElement("a")).build();
        assertEquals(0, XPathUtils.getNodeList(bElement, query).getLength());
        query = XPathQueryBuilder.allFromCurrentPosition().element(getElement("b")).build();
        assertEquals(0, XPathUtils.getNodeList(bElement, query).getLength());
        query = XPathQueryBuilder.allFromCurrentPosition().element(getElement("c")).build();
        assertEquals(0, XPathUtils.getNodeList(bElement, query).getLength());
        query = XPathQueryBuilder.allFromCurrentPosition().element(getElement("d")).build();
        assertEquals(1, XPathUtils.getNodeList(bElement, query).getLength());
        query = XPathQueryBuilder.allFromCurrentPosition().element(getElement("e")).build();
        assertEquals(2, XPathUtils.getNodeList(bElement, query).getLength());

        query = XPathQueryBuilder.fromCurrentPosition().element(getElement("a")).build();
        assertEquals(0, XPathUtils.getNodeList(bElement, query).getLength());
        query = XPathQueryBuilder.fromCurrentPosition().element(getElement("b")).build();
        assertEquals(0, XPathUtils.getNodeList(bElement, query).getLength());
        query = XPathQueryBuilder.fromCurrentPosition().element(getElement("c")).build();
        assertEquals(0, XPathUtils.getNodeList(bElement, query).getLength());
        query = XPathQueryBuilder.fromCurrentPosition().element(getElement("d")).build();
        assertEquals(1, XPathUtils.getNodeList(bElement, query).getLength());
        query = XPathQueryBuilder.fromCurrentPosition().element(getElement("e")).build();
        assertEquals(1, XPathUtils.getNodeList(bElement, query).getLength());
    }

    @Test
    public void elementPathTest() {
        XPathQuery query = XPathQueryBuilder.all().elements(getElement("a"), getElement("b")).build();
        assertEquals(1, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.all().elements(getElement("a"), getElement("c")).build();
        assertEquals(1, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.all().elements(getElement("b"), getElement("c")).build();
        assertEquals(0, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.all().elements(getElement("b"), getElement("d")).build();
        assertEquals(1, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.all().elements(getElement("c"), getElement("d")).build();
        assertEquals(2, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.all().elements(getElement("b"), getElement("e")).build();
        assertEquals(1, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.all().elements(getElement("e"), getElement("e")).build();
        assertEquals(1, XPathUtils.getNodeList(DOC, query).getLength());
    }

    @Test
    public void attributeTest() {
        XPathQuery query = XPathQueryBuilder.all().attribute(getAttribute("pos")).build();
        assertEquals(1, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.all().attribute(getAttribute("Id")).build();
        assertEquals(1, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.all().attribute(getAttribute("id")).build();
        assertEquals(0, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.all().attribute(getAttribute("evil")).build();
        assertEquals(0, XPathUtils.getNodeList(DOC, query).getLength());
    }

    @Test
    public void attributeValueTest() {
        XPathQuery query = XPathQueryBuilder.all().attribute(getAttribute("pos"), "nested").build();
        assertEquals(1, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.all().attribute(getAttribute("pos"), "notnested").build();
        assertEquals(0, XPathUtils.getNodeList(DOC, query).getLength());
    }

    @Test
    public void idAttributeTest() {
        XPathQuery query = XPathQueryBuilder.all().idValue("world").build();
        assertEquals(1, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.all().idValue("void").build();
        assertEquals(0, XPathUtils.getNodeList(DOC, query).getLength());
    }

    @Test
    public void notChildOfTest() {
        XPathQuery query = XPathQueryBuilder.all().element(getElement("d")).notChildOf(getElement("b")).build();
        assertEquals(2, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.all().element(getElement("d")).notChildOf(getElement("c")).build();
        assertEquals(1, XPathUtils.getNodeList(DOC, query).getLength());
        query = XPathQueryBuilder.all().element(getElement("d")).notChildOf(getElement("a")).build();
        assertEquals(3, XPathUtils.getNodeList(DOC, query).getLength());
    }

    private DSSElement getElement(String localName) {
        return DSSElement.fromDefinition(localName, null);
    }

    private DSSAttribute getAttribute(String localName) {
        return DSSAttribute.fromDefinition(localName);
    }
    
}
