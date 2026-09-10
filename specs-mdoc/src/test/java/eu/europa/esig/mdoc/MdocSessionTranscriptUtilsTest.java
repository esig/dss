package eu.europa.esig.mdoc;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MdocSessionTranscriptUtilsTest {

    private static MdocSessionTranscriptUtils mdocSessionTranscriptUtils;

    @BeforeAll
    static void init() {
        mdocSessionTranscriptUtils = MdocSessionTranscriptUtils.getInstance();
    }

    @Test
    void validMdocSessionTranscriptTest() {
        InputStream is = MdocSessionTranscriptUtilsTest.class.getResourceAsStream("/session_transcript_valid.cbor");

        List<String> errors = mdocSessionTranscriptUtils.validateAgainstSchema(is);
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void validMdocSessionTranscriptRootDefinedTest() {
        InputStream is = MdocSessionTranscriptUtilsTest.class.getResourceAsStream("/session_transcript_valid.cbor");

        List<String> errors = mdocSessionTranscriptUtils.validateAgainstSchema(is, MdocSessionTranscriptUtils.SESSION_TRANSCRIPT);
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void validMdocSessionTranscriptWrongRootDefinedTest() {
        InputStream is = MdocSessionTranscriptUtilsTest.class.getResourceAsStream("/session_transcript_valid.cbor");

        List<String> errors = mdocSessionTranscriptUtils.validateAgainstSchema(is, MdocSessionTranscriptUtils.SESSION_TRANSCRIPT_BYTES);
        assertFalse(errors.isEmpty(), errors.toString());
    }

    @Test
    void invalidMdocSessionTranscriptTest() {
        InputStream is = MdocSessionTranscriptUtilsTest.class.getResourceAsStream("/session_transcript_invalid.cbor");

        List<String> errors = mdocSessionTranscriptUtils.validateAgainstSchema(is);
        assertFalse(errors.isEmpty());
        assertEquals(1, errors.size(), errors.toString());
        assertTrue(errors.get(0).contains("tagged"), errors.toString());
    }

    @Test
    void deviceResponseTest() {
        InputStream is = MdocSessionTranscriptUtilsTest.class.getResourceAsStream("/mdoc_valid.cbor");

        List<String> errors = mdocSessionTranscriptUtils.validateAgainstSchema(is);
        assertFalse(errors.isEmpty());
    }

}
