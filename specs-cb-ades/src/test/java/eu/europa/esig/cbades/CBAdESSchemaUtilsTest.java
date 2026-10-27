package eu.europa.esig.cbades;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CBAdESSchemaUtilsTest {

    private static CBAdESSchemaUtils cbadesSchemaUtils;

    @BeforeAll
    static void init() {
        cbadesSchemaUtils = CBAdESSchemaUtils.getInstance();
    }

    @Test
    void coseSign1TaggedValidTest() {
        InputStream is = CBAdESSchemaUtilsTest.class.getResourceAsStream("/cose_sign1_tagged.cose");

        List<String> errors = cbadesSchemaUtils.validateAgainstSchema(is);
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void coseSign1TaggedWithSigDInvalidTest() {
        InputStream is = CBAdESSchemaUtilsTest.class.getResourceAsStream("/cose_sign1_tagged_sigD_invalid.cose");

        List<String> errors = cbadesSchemaUtils.validateAgainstSchema(is);
        assertFalse(errors.isEmpty(), errors.toString());
        assertEquals(1, errors.size(), errors.toString());
        assertTrue(errors.get(0).contains("[/[0]/.cbor/267/1]"));
        assertTrue(errors.get(0).contains("(#6.32)"));
    }

    @Test
    void coseSign1TaggedWithCounterSignatureV2Test() {
        InputStream is = CBAdESSchemaUtilsTest.class.getResourceAsStream("/cose_sign1_tagged_with countersignatureV2_tagged.cose");

        List<String> errors = cbadesSchemaUtils.validateAgainstSchema(is);
        assertFalse(errors.isEmpty(), errors.toString());
        assertEquals(1, errors.size());
        assertTrue(errors.get(0).contains("[/[1]/268[0]/.cbor/11]"));
    }

}
