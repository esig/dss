package eu.europa.esig.dss.pki.jaxb;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PKIJaxbFacadeTest extends AbstractTestJaxbPKI {

    public static Stream<Arguments> data() {
        File folder = new File(PKIJaxbFacadeTest.class.getClassLoader().getResource(XML_FOLDER).getPath());
        List<Arguments> dataToRun = new ArrayList<>();
        for (File file : folder.listFiles()) {
            dataToRun.add(Arguments.of(file));
        }
        return dataToRun.stream();
    }

    @ParameterizedTest(name = "PKI {index} : {0}")
    @MethodSource("data")
    public void testUnmarshall(File pkiFile) throws XMLStreamException, JAXBException, IOException, SAXException {
        XmlPki xmlPki = PKIJaxbFacade.newFacade().unmarshall(pkiFile);
        assertNotNull(xmlPki);
        assertTrue(xmlPki.getCertificate().size() > 0);
    }

}
