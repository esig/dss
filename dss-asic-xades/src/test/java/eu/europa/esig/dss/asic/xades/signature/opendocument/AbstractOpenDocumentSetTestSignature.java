package eu.europa.esig.dss.asic.xades.signature.opendocument;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

public abstract class AbstractOpenDocumentSetTestSignature extends AbstractOpenDocumentTestSignature {

    protected DSSDocument fileToTest;

    protected static Stream<Arguments> data() {
        File folder = new File("src/test/resources/opendocument");
        Collection<File> listFiles = Utils.listFiles(folder,
                new String[] { "odt", "ods", "odp", "odg" }, true);

        List<Arguments> args = new ArrayList<>();
        for (File file : listFiles) {
            args.add(Arguments.of(new FileDocument(file)));
        }
        return args.stream();
    }

    @ParameterizedTest(name = "Validation {index} : {0}")
    @MethodSource("data")
    public void test(DSSDocument fileToTest) {
        this.fileToTest = fileToTest;

        super.signAndVerify();
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return fileToTest;
    }

    @Override
    public void signAndVerify() {
    }

}
