package eu.europa.esig.dss.xml.utils.xpath;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.xml.common.definition.DSSAttribute;
import eu.europa.esig.dss.xml.common.definition.DSSElement;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.common.xpath.XPathQuery;
import eu.europa.esig.dss.xml.common.xpath.XPathQueryBuilder;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.NamespaceContextMap;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XPathUtilsTest {

    private static final Document DOC = DomUtils.buildDOM("<a><b><d>Hello</d><e><e pos=\"nested\">Nested</e></e></b><c><d>Bye</d><d Id=\"world\">World</d></c></a>");

    @Test
    void registerNamespaceTest() {
        DSSNamespace manifestNamespace = new DSSNamespace("urn:dss:namespace", "dss");

        NamespaceContextMap namespaceContextMap = XPathUtils.getNamespaceContextMap();
        assertEquals("", namespaceContextMap.getNamespaceURI("dss"));

        XPathUtils.registerNamespace(manifestNamespace);
        assertEquals("urn:dss:namespace", namespaceContextMap.getNamespaceURI("dss"));

        Exception exception = assertThrows(UnsupportedOperationException.class,
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

        assertNotNull(XPathUtils.getElementById(DOC, "world"));
        assertNull(XPathUtils.getElementById(DOC, "nested"));
        assertNull(XPathUtils.getElementById(DOC, "hello"));

        XPathQuery query = XPathQueryBuilder.allFromCurrentPosition().elements(getElement("a"), getElement("c"), getElement("d")).build();
        assertNotNull(XPathUtils.getElementById(DOC, query, "world"));
        query = XPathQueryBuilder.allFromCurrentPosition().elements(getElement("a"), getElement("b"), getElement("d")).build();
        assertNull(XPathUtils.getElementById(DOC, query, "world"));
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

    @Test
    public void getValueTest() {
        Node bElement = DOC.getDocumentElement().getFirstChild();

        XPathQuery query = XPathQueryBuilder.fromCurrentPosition().element(getElement("d")).build();
        assertEquals("Hello", XPathUtils.getValue(bElement, query));
        query = XPathQueryBuilder.allFromCurrentPosition().element(getElement("d")).build();
        assertEquals("Hello", XPathUtils.getValue(bElement, query));
        query = XPathQueryBuilder.fromCurrentPosition().element(getElement("e")).build();
        assertEquals("Nested", XPathUtils.getValue(bElement, query));
        query = XPathQueryBuilder.fromCurrentPosition().elements(getElement("e"), getElement("e")).build();
        assertEquals("Nested", XPathUtils.getValue(bElement, query));
        query = XPathQueryBuilder.fromCurrentPosition().element(getElement("g")).build();
        assertNull(XPathUtils.getValue(bElement, query));

        assertThrows(DSSException.class, () -> XPathUtils.getValue(bElement,
                XPathQueryBuilder.allFromCurrentPosition().element(getElement("e")).build()));
    }

    @Test
    public void getNodeTest() {
        Node bElement = DOC.getDocumentElement().getFirstChild();

        XPathQuery query = XPathQueryBuilder.fromCurrentPosition().element(getElement("d")).build();
        assertNotNull(XPathUtils.getNode(bElement, query));
        query = XPathQueryBuilder.allFromCurrentPosition().element(getElement("d")).build();
        assertNotNull(XPathUtils.getNode(bElement, query));
        query = XPathQueryBuilder.fromCurrentPosition().element(getElement("e")).build();
        assertNotNull(XPathUtils.getNode(bElement, query));
        query = XPathQueryBuilder.fromCurrentPosition().elements(getElement("e"), getElement("e")).build();
        assertNotNull(XPathUtils.getNode(bElement, query));
        query = XPathQueryBuilder.fromCurrentPosition().element(getElement("g")).build();
        assertNull(XPathUtils.getNode(bElement, query));

        assertThrows(DSSException.class, () -> XPathUtils.getNode(bElement,
                XPathQueryBuilder.allFromCurrentPosition().element(getElement("e")).build()));
    }

    @Test
    public void getElementTest() {
        Node bElement = DOC.getDocumentElement().getFirstChild();

        XPathQuery query = XPathQueryBuilder.fromCurrentPosition().element(getElement("d")).build();
        assertNotNull(XPathUtils.getElement(bElement, query));
        query = XPathQueryBuilder.allFromCurrentPosition().element(getElement("d")).build();
        assertNotNull(XPathUtils.getElement(bElement, query));
        query = XPathQueryBuilder.fromCurrentPosition().element(getElement("e")).build();
        assertNotNull(XPathUtils.getElement(bElement, query));
        query = XPathQueryBuilder.fromCurrentPosition().elements(getElement("e"), getElement("e")).build();
        assertNotNull(XPathUtils.getElement(bElement, query));
        query = XPathQueryBuilder.fromCurrentPosition().element(getElement("g")).build();
        assertNull(XPathUtils.getElement(bElement, query));

        assertThrows(DSSException.class, () -> XPathUtils.getElement(bElement,
                XPathQueryBuilder.allFromCurrentPosition().element(getElement("e")).build()));
    }

    @Test
    public void getNodesAmountTest() {
        Node bElement = DOC.getDocumentElement().getFirstChild();

        XPathQuery query = XPathQueryBuilder.fromCurrentPosition().element(getElement("d")).build();
        assertEquals(1, XPathUtils.getNodesAmount(bElement, query));
        query = XPathQueryBuilder.allFromCurrentPosition().element(getElement("d")).build();
        assertEquals(1, XPathUtils.getNodesAmount(bElement, query));
        query = XPathQueryBuilder.fromCurrentPosition().element(getElement("e")).build();
        assertEquals(1, XPathUtils.getNodesAmount(bElement, query));
        query = XPathQueryBuilder.fromCurrentPosition().elements(getElement("e"), getElement("e")).build();
        assertEquals(1, XPathUtils.getNodesAmount(bElement, query));
        query = XPathQueryBuilder.fromCurrentPosition().element(getElement("g")).build();
        assertEquals(0, XPathUtils.getNodesAmount(bElement, query));
        query = XPathQueryBuilder.allFromCurrentPosition().element(getElement("e")).build();
        assertEquals(2, XPathUtils.getNodesAmount(bElement, query));
    }

    @Test
    public void getChildrenNamesTest() {
        Node bElement = DOC.getDocumentElement().getFirstChild();

        XPathQuery query = XPathQueryBuilder.fromCurrentPosition().element(getElement("d")).build();
        assertEquals(Collections.emptyList(), XPathUtils.getChildrenNames(bElement, query));
        query = XPathQueryBuilder.fromCurrentPosition().element(getElement("e")).build();
        assertEquals(Collections.singletonList("e"), XPathUtils.getChildrenNames(bElement, query));
        query = XPathQueryBuilder.fromCurrentPosition().elements(getElement("e"), getElement("e")).build();
        assertEquals(Collections.emptyList(), XPathUtils.getChildrenNames(bElement, query));
        query = XPathQueryBuilder.fromCurrentPosition().element(getElement("g")).build();
        assertEquals(Collections.emptyList(), XPathUtils.getChildrenNames(bElement, query));
    }

    private DSSElement getElement(String localName) {
        return DSSElement.fromDefinition(localName, null);
    }

    private DSSAttribute getAttribute(String localName) {
        return DSSAttribute.fromDefinition(localName);
    }
    
}
