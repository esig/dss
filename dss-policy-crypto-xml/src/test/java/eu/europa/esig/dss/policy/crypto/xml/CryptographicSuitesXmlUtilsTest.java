package eu.europa.esig.dss.policy.crypto.xml;

import jakarta.xml.bind.JAXBException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class CryptographicSuitesXmlUtilsTest {

    private static CryptographicSuitesXmlUtils cryptographicSuitesXmlUtils;

    @BeforeAll
    static void init() {
        cryptographicSuitesXmlUtils = CryptographicSuitesXmlUtils.getInstance();
    }

    @Test
    void getJAXBContext() throws JAXBException {
        assertNotNull(cryptographicSuitesXmlUtils.getJAXBContext());
        // cached
        assertNotNull(cryptographicSuitesXmlUtils.getJAXBContext());
    }

    @Test
    void getSchema() throws SAXException {
        assertNotNull(cryptographicSuitesXmlUtils.getSchema());
        // cached
        assertNotNull(cryptographicSuitesXmlUtils.getSchema());
    }

}
