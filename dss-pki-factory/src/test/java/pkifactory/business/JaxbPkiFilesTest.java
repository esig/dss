package pkifactory.business;

import org.junit.jupiter.params.provider.Arguments;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public class JaxbPkiFilesTest {

    public static Stream<Arguments> data() {
        File folder = new File("src/main/resources/pki");
        List<Arguments> dataToRun = new ArrayList<>();
        for (File file : folder.listFiles()) {
            dataToRun.add(Arguments.of(file));
        }
        return dataToRun.stream();
    }


//    @ParameterizedTest(name = "PKI {index} : {0}")
//    @MethodSource("data")
//    public void testUnmarshall(File pkiFile) throws JAXBException {
//        Pki pki = (Pki) new JaxbConfig().getUnmarshaller().unmarshal(new StreamSource(pkiFile));
//        assertNotNull(pki);
//        assertTrue(pki.getCertificate().size() > 0);
//    }

}
