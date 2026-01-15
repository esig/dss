package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.xml.utils.xpath.NativeDOMXPathQueryExecutor;
import eu.europa.esig.dss.xml.utils.xpath.XPathQueryExecutorLoader;
import eu.europa.esig.dss.xml.utils.xpath.XPathUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class XPathSnippet {

    @Test
    void xPathConfiguration() {

        // tag::demo[]
        // import eu.europa.esig.dss.xml.utils.xpath.NativeDOMXPathQueryExecutor;
        // import eu.europa.esig.dss.xml.utils.xpath.XPathUtils;

        XPathUtils.setXPathQueryExecutor(new NativeDOMXPathQueryExecutor());
        // end::demo[]

        assertInstanceOf(NativeDOMXPathQueryExecutor.class, XPathUtils.getXPathQueryExecutor());
    }

    @AfterEach
    void clear() {
        XPathUtils.setXPathQueryExecutor(new XPathQueryExecutorLoader().getXPathQueryExecutor());
    }

}
