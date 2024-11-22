package eu.europa.esig.dss.tsl.parsing;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class TLStructureVerifierTest {

    private static final List<Integer> DEFAULT_ACCEPTED_TL_VERSION = Arrays.asList(5, 6);

    @Test
    void tlv4Test() {
        DSSDocument tlDocument = new FileDocument("src/test/resources/de-tl.xml");

        TLStructureVerifier tlStructureVerifier = new TLStructureVerifier();
        List<String> result = tlStructureVerifier.validate(tlDocument, 4);
        assertTrue(Utils.isCollectionEmpty(result));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, 4);
        assertTrue(result.stream().anyMatch(r -> r.contains("The TL Version '4' is not acceptable!")));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.validate(tlDocument, 5);
        assertTrue(Utils.isCollectionEmpty(result));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, 5);
        assertTrue(Utils.isCollectionEmpty(result));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.validate(tlDocument, 6);
        assertTrue(Utils.isCollectionEmpty(result));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, 6);
        assertTrue(result.stream().anyMatch(r -> r.contains("SigningCertificate")));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.validate(tlDocument, null);
        assertTrue(result.stream().anyMatch(r -> r.contains("No TLVersion has been found!")), result.toString());

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, null);
        assertTrue(result.stream().anyMatch(r -> r.contains("No TLVersion has been found!")), result.toString());
    }

    @Test
    void tlv5Test() {
        DSSDocument tlDocument = new FileDocument("src/test/resources/fr.xml");

        TLStructureVerifier tlStructureVerifier = new TLStructureVerifier();
        List<String> result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, 5);
        assertTrue(Utils.isCollectionEmpty(result));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.validate(tlDocument, 6);
        assertTrue(Utils.isCollectionEmpty(result));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, 6);
        assertTrue(result.stream().anyMatch(r -> r.contains("SigningCertificate")));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.validate(tlDocument, 4);
        assertTrue(Utils.isCollectionEmpty(result));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, 4);
        assertTrue(result.stream().anyMatch(r -> r.contains("The TL Version '4' is not acceptable!")));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.validate(tlDocument, null);
        assertTrue(result.stream().anyMatch(r -> r.contains("No TLVersion has been found!")), result.toString());

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, null);
        assertTrue(result.stream().anyMatch(r -> r.contains("No TLVersion has been found!")), result.toString());
    }

    @Test
    void tlv6Test() {
        DSSDocument tlDocument = new FileDocument("src/test/resources/fi-v6.xml");

        TLStructureVerifier tlStructureVerifier = new TLStructureVerifier();
        List<String> result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, 6);
        assertTrue(Utils.isCollectionEmpty(result));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.validate(tlDocument, 5);
        assertTrue(Utils.isCollectionEmpty(result));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, 5);
        assertTrue(result.stream().anyMatch(r -> r.contains("SigningCertificateV2")));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.validate(tlDocument, 4);
        assertTrue(Utils.isCollectionEmpty(result));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, 4);
        assertTrue(result.stream().anyMatch(r -> r.contains("The TL Version '4' is not acceptable!")));

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.validate(tlDocument, null);
        assertTrue(result.stream().anyMatch(r -> r.contains("No TLVersion has been found!")), result.toString());

        tlStructureVerifier = new TLStructureVerifier();
        result = tlStructureVerifier.setAcceptedTLVersions(DEFAULT_ACCEPTED_TL_VERSION).validate(tlDocument, null);
        assertTrue(result.stream().anyMatch(r -> r.contains("No TLVersion has been found!")), result.toString());
    }

}
