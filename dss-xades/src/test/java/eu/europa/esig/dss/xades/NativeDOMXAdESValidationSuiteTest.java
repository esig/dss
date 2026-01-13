package eu.europa.esig.dss.xades;

import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.xpath.NativeDOMXPathQueryExecutor;
import eu.europa.esig.dss.xml.utils.xpath.XPathQueryExecutorLoader;
import org.junit.platform.suite.api.AfterSuite;
import org.junit.platform.suite.api.BeforeSuite;
import org.junit.platform.suite.api.SelectPackages;
import org.junit.platform.suite.api.Suite;

@Suite
@SelectPackages(value = {"eu.europa.esig.dss.xades.signature", "eu.europa.esig.dss.xades.extension", "eu.europa.esig.dss.xades.validation"})
public class NativeDOMXAdESValidationSuiteTest {

    @BeforeSuite
    public static void init() {
        DomUtils.setXPathQueryExecutor(new NativeDOMXPathQueryExecutor());
    }

    @AfterSuite
    public static void clear() {
        // return to default
        DomUtils.setXPathQueryExecutor(new XPathQueryExecutorLoader().getExecutor());
    }

}
