package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.cookbook.example.CustomMimeTypeLoader;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class MimeTypeTest {

    @Test
    public void test() {
        assertEquals(CustomMimeTypeLoader.CustomMimeType.CSS, MimeType.fromFileName("style.css"));
        assertEquals(CustomMimeTypeLoader.CustomMimeType.WEBM, MimeType.fromFileName("audio.webm"));
        assertEquals(CustomMimeTypeLoader.CustomMimeType.JPEG, MimeType.fromFileName("image.jpeg"));

        assertEquals(CustomMimeTypeLoader.CustomMimeType.CSS, MimeType.fromMimeTypeString("text/css"));
        assertEquals(CustomMimeTypeLoader.CustomMimeType.WEBM, MimeType.fromMimeTypeString("audio/webm"));
        assertEquals(CustomMimeTypeLoader.CustomMimeType.JPEG, MimeType.fromMimeTypeString("image/jpeg"));
    }

    @Test
    public void defaultMimeTypeEnumTest() {
        assertEquals(MimeTypeEnum.TEXT, MimeType.fromFileName("text.txt"));
        assertEquals(MimeTypeEnum.TEXT, MimeType.fromMimeTypeString("text/plain"));
    }

    @Test
    public void notDefinedTest() {
        assertEquals(MimeTypeEnum.BINARY, MimeType.fromFileName("text.text"));
        assertEquals(MimeTypeEnum.BINARY, MimeType.fromMimeTypeString("text/new"));
    }

    @Test
    public void overwriteMimeTypeTest() {
        assertEquals(CustomMimeTypeLoader.CustomMimeType.CER, MimeType.fromFile(new File("D-TRUST_CA_3-1_2016.cer")));
        assertEquals(CustomMimeTypeLoader.CustomMimeType.CER, MimeType.fromFile(new File("src/test/resources/AdobeCA.p7c")));
    }

}
