package eu.europa.esig.mdoc;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MdocDeviceResponseUtilsTest {

    private static MdocDeviceResponseUtils mdocDeviceResponseUtils;

    @BeforeAll
    static void init() {
        mdocDeviceResponseUtils = MdocDeviceResponseUtils.getInstance();
    }

    @Test
    void validMdocDeviceResponseTest() {
        InputStream is = MdocDeviceResponseUtilsTest.class.getResourceAsStream("/mdoc_valid.cbor");

        List<String> errors = mdocDeviceResponseUtils.validateAgainstSchema(is);
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void validMdocDeviceResponseRootSpecifiedTest() {
        InputStream is = MdocDeviceResponseUtilsTest.class.getResourceAsStream("/mdoc_valid.cbor");

        List<String> errors = mdocDeviceResponseUtils.validateAgainstSchema(is, MdocDeviceResponseUtils.DEVICE_RESPONSE);
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void invalidMdocDeviceResponseTest() {
        InputStream is = MdocDeviceResponseUtilsTest.class.getResourceAsStream("/mdoc_invalid.cbor");

        List<String> errors = mdocDeviceResponseUtils.validateAgainstSchema(is);
        assertFalse(errors.isEmpty());
        assertEquals(2, errors.size());
        assertTrue(errors.stream().anyMatch(m -> m.contains("version")));
        assertTrue(errors.stream().anyMatch(m -> m.contains("{deviceSignature: DeviceSignature} / {deviceMac: DeviceMac}")));
    }

    @Test
    void issuerSignedTest() {
        InputStream is = MdocDeviceResponseUtilsTest.class.getResourceAsStream("/mdocIssuerSigned.cbor");

        List<String> errors = mdocDeviceResponseUtils.validateAgainstSchema(is);
        assertFalse(errors.isEmpty());
    }

    @Test
    void validMdocIssuerSignedTest() {
        InputStream is = MdocDeviceResponseUtilsTest.class.getResourceAsStream("/mdocIssuerSigned.cbor");

        List<String> errors = mdocDeviceResponseUtils.validateAgainstSchema(is, MdocDeviceResponseUtils.ISSUER_SIGNED);
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void invalidMdocIssuerSignedTest() {
        InputStream is = MdocDeviceResponseUtilsTest.class.getResourceAsStream("/mdocIssuerSigned_invalid.cbor");

        List<String> errors = mdocDeviceResponseUtils.validateAgainstSchema(is, MdocDeviceResponseUtils.ISSUER_SIGNED);
        assertFalse(errors.isEmpty());
        assertEquals(1, errors.size());
        assertTrue(errors.get(0).contains("#6.24"));
        assertTrue(errors.get(0).contains("IssuerSigned: "));
    }

    @Test
    void deviceResponseTest() {
        InputStream is = MdocDeviceResponseUtilsTest.class.getResourceAsStream("/mdoc_valid.cbor");

        List<String> errors = mdocDeviceResponseUtils.validateAgainstSchema(is, MdocDeviceResponseUtils.ISSUER_SIGNED);
        assertFalse(errors.isEmpty());
    }
    
}
