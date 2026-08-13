package eu.europa.esig.dss.jades.lote;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonLoTEStructureVerifierTest {

    @Test
    void validNoSigTest() {
        DSSDocument loteDocument = new FileDocument("src/test/resources/lote/lote-valid.json");

        JsonLoTEStructureVerifier verifier = new JsonLoTEStructureVerifier();

        verifier.setSigningMode(true);
        List<String> errors = verifier.validate(loteDocument);
        assertTrue(Utils.isCollectionEmpty(errors), errors.toString());

        verifier.setSigningMode(false);
        errors = verifier.validate(loteDocument);
        assertFalse(Utils.isCollectionEmpty(errors));
        assertTrue(errors.stream().anyMatch(r -> r.contains("The document is not conformant to the JWS Compact Serialization format!")), errors.toString());
    }

    @Test
    void invalidNoSigTest() {
        DSSDocument loteDocument = new FileDocument("src/test/resources/lote/lote-invalid.json");

        JsonLoTEStructureVerifier verifier = new JsonLoTEStructureVerifier();

        verifier.setSigningMode(true);
        List<String> errors = verifier.validate(loteDocument);
        assertFalse(Utils.isCollectionEmpty(errors), errors.toString());
        assertTrue(errors.stream().anyMatch(r -> r.contains("required properties are missing: LoTEVersionIdentifier")), errors.toString());

        verifier.setSigningMode(false);
        errors = verifier.validate(loteDocument);
        assertFalse(Utils.isCollectionEmpty(errors));
        assertTrue(errors.stream().anyMatch(r -> r.contains("The document is not conformant to the JWS Compact Serialization format!")), errors.toString());
    }

    @Test
    void validSignedTest() {
        DSSDocument loteDocument = new FileDocument("src/test/resources/lote/lote-valid-signed.json");

        JsonLoTEStructureVerifier verifier = new JsonLoTEStructureVerifier();

        verifier.setSigningMode(true);
        List<String> errors = verifier.validate(loteDocument);
        assertFalse(Utils.isCollectionEmpty(errors));
        assertTrue(errors.stream().anyMatch(r -> r.contains("The document is not a valid JSON document!")), errors.toString());

        verifier.setSigningMode(false);
        errors = verifier.validate(loteDocument);
        assertTrue(Utils.isCollectionEmpty(errors));
    }

    @Test
    void nonLoTETest() {
        DSSDocument document = new FileDocument("src/test/resources/sample.json");

        JsonLoTEStructureVerifier verifier = new JsonLoTEStructureVerifier();

        verifier.setSigningMode(true);
        List<String> errors = verifier.validate(document);
        assertFalse(Utils.isCollectionEmpty(errors));
        assertTrue(errors.stream().anyMatch(r -> r.contains("required properties are missing: LoTE")), errors.toString());

        verifier.setSigningMode(false);
        errors = verifier.validate(document);
        assertFalse(Utils.isCollectionEmpty(errors));
        assertTrue(errors.stream().anyMatch(r -> r.contains("The document is not conformant to the JWS Compact Serialization format!")), errors.toString());
    }

    @Test
    void nonJsonTest() {
        DSSDocument document = new FileDocument("src/test/resources/sample.png");

        JsonLoTEStructureVerifier verifier = new JsonLoTEStructureVerifier();

        verifier.setSigningMode(true);
        List<String> errors = verifier.validate(document);
        assertFalse(Utils.isCollectionEmpty(errors));
        assertTrue(errors.stream().anyMatch(r -> r.contains("The document is not a valid JSON document!")), errors.toString());

        verifier.setSigningMode(false);
        errors = verifier.validate(document);
        assertFalse(Utils.isCollectionEmpty(errors));
        assertTrue(errors.stream().anyMatch(r -> r.contains("The document is not conformant to the JWS Compact Serialization format!")), errors.toString());
    }

    @Test
    void nullTest() {
        JsonLoTEStructureVerifier verifier = new JsonLoTEStructureVerifier();

        Exception exception = assertThrows(NullPointerException.class, () -> verifier.validate((DSSDocument) null));
        assertEquals("Document to be validated cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> verifier.validate((String) null));
        assertEquals("Document to be validated cannot be null!", exception.getMessage());

        verifier.setSigningMode(true);

        exception = assertThrows(NullPointerException.class, () -> verifier.validate((DSSDocument) null));
        assertEquals("Document to be validated cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> verifier.validate((String) null));
        assertEquals("Document to be validated cannot be null!", exception.getMessage());

        verifier.setSigningMode(false);

        exception = assertThrows(NullPointerException.class, () -> verifier.validate((DSSDocument) null));
        assertEquals("Document to be validated cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> verifier.validate((String) null));
        assertEquals("Document to be validated cannot be null!", exception.getMessage());
    }

}
