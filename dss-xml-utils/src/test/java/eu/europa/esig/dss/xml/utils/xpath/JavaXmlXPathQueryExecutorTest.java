package eu.europa.esig.dss.xml.utils.xpath;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.xml.common.definition.DSSElement;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.common.xpath.XPathQuery;
import eu.europa.esig.dss.xml.common.xpath.XPathQueryBuilder;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.NamespaceContextMap;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JavaXmlXPathQueryExecutorTest extends AbstractTestXPathQueryExecutor {

    private static final String XML_WITH_NAMESPACE = "<m:manifest xmlns:m=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\"><m:file-entry m:media-type=\"text/plain\" m:full-path=\"hello.txt\" /></m:manifest>";

    @Override
    protected XPathQueryExecutor getExecutor() {
        return new JavaXmlXPathQueryExecutor();
    }

    @Test
    void registerNamespaceTest() {
        Document document = DomUtils.buildDOM(XML_WITH_NAMESPACE);

        XPathQueryExecutor executor = getExecutor();

        NamespaceContextMap namespaceContextMap = new NamespaceContextMap();
        executor.setNamespaceContext(namespaceContextMap);

        DSSNamespace manifestNamespace = new DSSNamespace("urn:oasis:names:tc:opendocument:xmlns:manifest:1.0", "m");
        final XPathQuery xPathQuery = XPathQueryBuilder.fromCurrentPosition()
                .element(DSSElement.fromDefinition("file-entry", manifestNamespace)).build();
        Exception exception = assertThrows(DSSException.class, () -> executor.getNodeList(document.getDocumentElement(), xPathQuery));
        assertTrue(exception.getMessage().contains("Unable to create an XPath expression"));

        namespaceContextMap.registerNamespace(manifestNamespace.getPrefix(), manifestNamespace.getUri());

        NodeList fileEntryNodeList = executor.getNodeList(document.getDocumentElement(), xPathQuery);
        assertEquals(1, fileEntryNodeList.getLength());
        assertNotNull(fileEntryNodeList.item(0));
    }

}
