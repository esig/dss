package eu.europa.esig.dss.cookbook.example;

import eu.europa.esig.dss.enumerations.MimeType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class MimeTypeTest {

    @Test
    public void test() {
        assertEquals(CustomMimeTypeLoader.CustomMimeType.CUSTOM, MimeType.fromFileExtension(""));
    }

}
