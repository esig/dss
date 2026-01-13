package eu.europa.esig.dss.xml.utils.xpath;

class JavaXmlXPathQueryExecutorTest extends AbstractTestXPathQueryExecutor {

    @Override
    protected XPathQueryExecutor getExecutor() {
        return new JavaXmlXPathQueryExecutor();
    }

}
