package eu.europa.esig.dss.policy.crypto.xml;

import jakarta.xml.bind.JAXBException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class CryptographicSuiteXmlUtilsTest {

    private static CryptographicSuiteXmlUtils cryptographicSuiteXmlUtils;

    @BeforeAll
    static void init() {
        cryptographicSuiteXmlUtils = CryptographicSuiteXmlUtils.getInstance();
    }

    @Test
    void getJAXBContext() throws JAXBException {
        assertNotNull(cryptographicSuiteXmlUtils.getJAXBContext());
        // cached
        assertNotNull(cryptographicSuiteXmlUtils.getJAXBContext());
    }

    @Test
    void getSchema() throws SAXException {
        assertNotNull(cryptographicSuiteXmlUtils.getSchema());
        // cached
        assertNotNull(cryptographicSuiteXmlUtils.getSchema());
    }

}
