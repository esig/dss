package eu.europa.esig.xmlers;

import eu.europa.esig.ers.xmlers.jaxb.EvidenceRecordType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import java.io.File;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class XMLEvidenceRecordTest {

    private static XMLEvidenceRecordUtils xmlersUtils;

    @BeforeAll
    public static void init() {
        xmlersUtils = XMLEvidenceRecordUtils.getInstance();
    }

    private static Stream<Arguments> data() {
        File folder = new File("src/test/resources");
        Collection<Arguments> dataToRun = new ArrayList<>();
        for (File file : getDirectoryFiles(folder)) {
            dataToRun.add(Arguments.of(file));
        }
        return dataToRun.stream();
    }

    private static List<File> getDirectoryFiles(File file) {
        List<File> result = new ArrayList<>();
        if (file.isFile()) {
            result.add(file);
        } else if (file.isDirectory()) {
            for (File subFile : file.listFiles()) {
                result.addAll(getDirectoryFiles(subFile));
            }
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    @ParameterizedTest(name = "Validation {index} : {0}")
    @MethodSource("data")
    public void testMarshalling(File xmlersFile) throws JAXBException, SAXException {
        JAXBContext jc = xmlersUtils.getJAXBContext();
        assertNotNull(jc);

        Schema schema = xmlersUtils.getSchema();
        assertNotNull(schema);

        Unmarshaller unmarshaller = jc.createUnmarshaller();
        unmarshaller.setSchema(schema);

        JAXBElement<EvidenceRecordType> unmarshalled = (JAXBElement<EvidenceRecordType>) unmarshaller.unmarshal(xmlersFile);
        assertNotNull(unmarshalled);
        assertNotNull(unmarshalled.getValue());

        Marshaller marshaller = jc.createMarshaller();
        marshaller.setSchema(schema);

        StringWriter sw = new StringWriter();
        marshaller.marshal(unmarshalled, sw);

        String xmlerString = sw.toString();

        JAXBElement<EvidenceRecordType> unmarshalled2 = (JAXBElement<EvidenceRecordType>) unmarshaller.unmarshal(new StringReader(xmlerString));
        assertNotNull(unmarshalled2);
        assertNotNull(unmarshalled2.getValue());
    }

    @Test
    public void getJAXBContext() throws JAXBException {
        assertNotNull(xmlersUtils.getJAXBContext());
        // cached
        assertNotNull(xmlersUtils.getJAXBContext());
    }

}
