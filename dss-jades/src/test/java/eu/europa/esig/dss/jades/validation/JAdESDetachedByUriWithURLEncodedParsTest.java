package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.Arrays;
import java.util.List;

public class JAdESDetachedByUriWithURLEncodedParsTest extends AbstractJAdESTestValidation {

    private static final String DOC_ONE_NAME = "https://nowina.lu/pub/JAdES/ObjectIdByURI-1.html";
    private static final String DOC_TWO_NAME = "https://nowina.lu/pub/JAdES/ObjectIdByURI-2.html";

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/jades-detached-by-uri-encoded-pars.json");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        DSSDocument documentOne = new FileDocument("src/test/resources/ObjectIdByURI-1.html");
        documentOne.setName(DOC_ONE_NAME);
        DSSDocument documentTwo = new FileDocument("src/test/resources/ObjectIdByURI-2.html");
        documentTwo.setName(DOC_TWO_NAME);
        return Arrays.asList(documentOne, documentTwo);
    }

}
