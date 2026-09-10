package eu.europa.esig.mdoc;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MdocMobileSecurityObjectUtilsTest {

    private static MdocMobileSecurityObjectUtils mdocMobileSecurityObjectUtils;

    @BeforeAll
    static void init() {
        mdocMobileSecurityObjectUtils = MdocMobileSecurityObjectUtils.getInstance();
    }

    @Test
    void validMdocMSOTest() {
        InputStream is = MdocMobileSecurityObjectUtilsTest.class.getResourceAsStream("/mso_valid.cbor");

        List<String> errors = mdocMobileSecurityObjectUtils.validateAgainstSchema(is);
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void validMdocMSRootDefinedTest() {
        InputStream is = MdocMobileSecurityObjectUtilsTest.class.getResourceAsStream("/mso_valid.cbor");

        List<String> errors = mdocMobileSecurityObjectUtils.validateAgainstSchema(is, MdocMobileSecurityObjectUtils.MOBILE_SECURITY_OBJECT_BYTES);
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void validMdocMSWrongRootDefinedTest() {
        InputStream is = MdocMobileSecurityObjectUtilsTest.class.getResourceAsStream("/mso_valid.cbor");

        List<String> errors = mdocMobileSecurityObjectUtils.validateAgainstSchema(is, MdocMobileSecurityObjectUtils.MOBILE_SECURITY_OBJECT);
        assertFalse(errors.isEmpty(), errors.toString());
    }

    @Test
    void invalidMdocMSOTest() {
        InputStream is = MdocMobileSecurityObjectUtilsTest.class.getResourceAsStream("/mso_invalid.cbor");

        List<String> errors = mdocMobileSecurityObjectUtils.validateAgainstSchema(is);
        assertFalse(errors.isEmpty());
        assertEquals(1, errors.size());
        assertTrue(errors.get(0).contains("Unexpected key '1'"), errors.toString());
    }

    @Test
    void deviceResponseTest() {
        InputStream is = MdocMobileSecurityObjectUtilsTest.class.getResourceAsStream("/mdoc_valid.cbor");

        List<String> errors = mdocMobileSecurityObjectUtils.validateAgainstSchema(is);
        assertFalse(errors.isEmpty());
    }
    
}
