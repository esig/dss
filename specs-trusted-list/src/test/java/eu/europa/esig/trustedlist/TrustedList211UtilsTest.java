package eu.europa.esig.trustedlist;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.UnmarshalException;
import jakarta.xml.bind.Unmarshaller;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import javax.xml.validation.Schema;
import java.io.File;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TrustedList211UtilsTest {

    private static TrustedList211Utils trustedList211Utils;

    @BeforeAll
    static void init() {
        trustedList211Utils = TrustedList211Utils.getInstance();
    }

    @Test
    void getJAXBContext() throws JAXBException {
        assertNotNull(trustedList211Utils.getJAXBContext());
        // cached
        assertNotNull(trustedList211Utils.getJAXBContext());
    }

    @Test
    void getSchema() throws SAXException {
        assertNotNull(trustedList211Utils.getSchema());
        // cached
        assertNotNull(trustedList211Utils.getSchema());
    }

    @Test
    void lotlTest() throws JAXBException, SAXException {
        File xmldsigFile = new File("src/test/resources/lotl.xml");
        marshallUnmarshall(xmldsigFile);
    }

    @Test
    void tlTest() throws JAXBException, SAXException {
        File xmldsigFile = new File("src/test/resources/tl.xml");
        marshallUnmarshall(xmldsigFile);
    }

    @Test
    void tlv5Test() throws JAXBException, SAXException {
        File xmldsigFile = new File("src/test/resources/tlv5.xml");
        marshallUnmarshall(xmldsigFile);
    }

    @Test
    void tlv6Test() {
        File xmldsigFile = new File("src/test/resources/tlv6.xml");
        UnmarshalException exception = assertThrows(UnmarshalException.class, () -> marshallUnmarshall(xmldsigFile));
        assertTrue(exception.getCause().getMessage().contains("ServiceSupplyPoint"));
    }

    private void marshallUnmarshall(File xmlFile) throws JAXBException, SAXException {
        JAXBContext jc = trustedList211Utils.getJAXBContext();
        assertNotNull(jc);

        Schema schema = trustedList211Utils.getSchema();
        assertNotNull(schema);

        Unmarshaller unmarshaller = jc.createUnmarshaller();
        unmarshaller.setSchema(schema);

        JAXBElement<?> unmarshalled = (JAXBElement<?>) unmarshaller.unmarshal(xmlFile);
        assertNotNull(unmarshalled);
    }

}
