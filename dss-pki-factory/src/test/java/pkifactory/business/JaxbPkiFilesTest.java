package pkifactory.business;

import eu.europa.esig.dss.pki.Pki;
import eu.europa.esig.dss.pki.config.JaxbConfig;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.xml.bind.JAXBException;
import javax.xml.transform.stream.StreamSource;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

//@ContextConfiguration(classes = JaxbConfig.class)
public class JaxbPkiFilesTest {

    public static Stream<Arguments> data() {
        File folder = new File("src/main/resources/pki");
        List<Arguments> dataToRun = new ArrayList<>();
        for (File file : folder.listFiles()) {
            dataToRun.add(Arguments.of(file));
        }
        return dataToRun.stream();
    }

    //	@Autowired
    private JaxbConfig unmarshaller = new JaxbConfig();

    public JaxbPkiFilesTest() throws Exception {
//		new TestContextManager(getClass()).prepareTestInstance(this);
    }

    @ParameterizedTest(name = "PKI {index} : {0}")
    @MethodSource("data")
    public void testUnmarshall(File pkiFile) throws IOException, JAXBException {
        Pki pki = (Pki) unmarshaller.unmarshaller().unmarshal(new StreamSource(pkiFile));
        assertNotNull(pki);
        assertTrue(pki.getCertificate().size() > 0);
    }

}
