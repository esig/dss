package eu.europa.esig.dss.xml.utils.xpath;

class NativeDOMXPathQueryExecutorTest extends AbstractTestXPathQueryExecutor {

    @Override
    protected XPathQueryExecutor getExecutor() {
        return new NativeDOMXPathQueryExecutor();
    }

}
