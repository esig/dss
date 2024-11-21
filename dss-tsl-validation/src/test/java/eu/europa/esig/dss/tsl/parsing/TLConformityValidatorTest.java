package eu.europa.esig.dss.tsl.parsing;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class TLConformityValidatorTest {

    @Test
    void tlv4Test() {
        DSSDocument tlDocument = new FileDocument("src/test/resources/de-tl.xml");

        TLConformityValidator tlConformityValidator = new TLConformityValidator(tlDocument, 4);
        List<String> result = tlConformityValidator.validate();
        assertTrue(Utils.isCollectionEmpty(result));

        tlConformityValidator = new TLConformityValidator(tlDocument, 5);
        result = tlConformityValidator.validate();
        assertTrue(Utils.isCollectionEmpty(result));

        tlConformityValidator = new TLConformityValidator(tlDocument, 6);
        result = tlConformityValidator.validate();
        assertTrue(result.stream().anyMatch(r -> r.contains("SigningCertificate")));

        tlConformityValidator = new TLConformityValidator(tlDocument, null);
        result = tlConformityValidator.validate();
        assertTrue(result.stream().anyMatch(r -> r.contains("No TLVersion has been found!")), result.toString());
    }

    @Test
    void tlv5Test() {
        DSSDocument tlDocument = new FileDocument("src/test/resources/fr.xml");

        TLConformityValidator tlConformityValidator = new TLConformityValidator(tlDocument, 5);
        List<String> result = tlConformityValidator.validate();
        assertTrue(Utils.isCollectionEmpty(result));

        tlConformityValidator = new TLConformityValidator(tlDocument, 6);
        result = tlConformityValidator.validate();
        assertTrue(result.stream().anyMatch(r -> r.contains("SigningCertificate")));

        tlConformityValidator = new TLConformityValidator(tlDocument, 4);
        result = tlConformityValidator.validate();
        assertTrue(Utils.isCollectionEmpty(result));

        tlConformityValidator = new TLConformityValidator(tlDocument, null);
        result = tlConformityValidator.validate();
        assertTrue(result.stream().anyMatch(r -> r.contains("No TLVersion has been found!")), result.toString());
    }

    @Test
    void tlv6Test() {
        DSSDocument tlDocument = new FileDocument("src/test/resources/fi-v6.xml");

        TLConformityValidator tlConformityValidator = new TLConformityValidator(tlDocument, 6);
        List<String> result = tlConformityValidator.validate();
        assertTrue(Utils.isCollectionEmpty(result));

        tlConformityValidator = new TLConformityValidator(tlDocument, 5);
        result = tlConformityValidator.validate();
        assertTrue(result.stream().anyMatch(r -> r.contains("SigningCertificateV2")));

        tlConformityValidator = new TLConformityValidator(tlDocument, 4);
        result = tlConformityValidator.validate();
        assertTrue(Utils.isCollectionEmpty(result));

        tlConformityValidator = new TLConformityValidator(tlDocument, null);
        result = tlConformityValidator.validate();
        assertTrue(result.stream().anyMatch(r -> r.contains("No TLVersion has been found!")), result.toString());
    }

}
