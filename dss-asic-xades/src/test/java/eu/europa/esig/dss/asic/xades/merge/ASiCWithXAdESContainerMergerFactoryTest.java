package eu.europa.esig.dss.asic.xades.merge;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.merge.ASiCContainerMerger;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCWithXAdESContainerMergerFactoryTest {

    @Test
    public void isSupportedDSSDocumentTest() {
        ASiCWithXAdESContainerMergerFactory factory = new ASiCWithXAdESContainerMergerFactory();
        assertTrue(factory.isSupported(new FileDocument("src/test/resources/validation/onefile-ok.asics")));
        assertTrue(factory.isSupported(new FileDocument("src/test/resources/validation/multifiles-ok.asics")));
        assertTrue(factory.isSupported(new FileDocument("src/test/resources/signable/test.zip"))); // simple container
        assertTrue(factory.isSupported(new FileDocument("src/test/resources/validation/onefile-ok.asice")));
        assertTrue(factory.isSupported(new FileDocument("src/test/resources/validation/multifiles-ok.asice")));
        assertTrue(factory.isSupported(new FileDocument("src/test/resources/signable/asic_xades.zip"))); // ASiC-E
        assertTrue(factory.isSupported(new FileDocument("src/test/resources/signable/open-document.odt")));
        assertFalse(factory.isSupported(new FileDocument("src/test/resources/signable/asic_cades.zip")));
        assertFalse(factory.isSupported(new FileDocument("src/test/resources/signable/test.txt")));
    }

    @Test
    public void isSupportedMultipleDSSDocumentTest() {
        ASiCWithXAdESContainerMergerFactory factory = new ASiCWithXAdESContainerMergerFactory();
        assertTrue(factory.isSupported(
                new FileDocument("src/test/resources/validation/onefile-ok.asics"),
                new FileDocument("src/test/resources/validation/multifiles-ok.asics")));
        assertTrue(factory.isSupported(
                new FileDocument("src/test/resources/validation/onefile-ok.asics"),
                new FileDocument("src/test/resources/signable/test.zip")));
        assertTrue(factory.isSupported(
                new FileDocument("src/test/resources/validation/onefile-ok.asics"),
                new FileDocument("src/test/resources/validation/multifiles-ok.asics"),
                new FileDocument("src/test/resources/signable/test.zip")));
        assertFalse(factory.isSupported(
                new FileDocument("src/test/resources/validation/onefile-ok.asics"),
                new FileDocument("src/test/resources/signable/asic_cades.zip")));
        assertFalse(factory.isSupported(
                new FileDocument("src/test/resources/signable/test.txt"),
                new FileDocument("src/test/resources/signable/asic_cades.zip")));
    }

    @Test
    public void isSupportedASiCContentTest() {
        ASiCWithXAdESContainerMergerFactory factory = new ASiCWithXAdESContainerMergerFactory();
        assertTrue(factory.isSupported(new ASiCWithXAdESContainerExtractor(
                new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract()));
        assertTrue(factory.isSupported(new ASiCWithXAdESContainerExtractor(
                new FileDocument("src/test/resources/validation/multifiles-ok.asics")).extract()));
        assertTrue(factory.isSupported(new ASiCWithXAdESContainerExtractor(
                new FileDocument("src/test/resources/signable/test.zip")).extract()));
        assertTrue(factory.isSupported(new ASiCWithXAdESContainerExtractor(
                new FileDocument("src/test/resources/validation/onefile-ok.asice")).extract()));
        assertTrue(factory.isSupported(new ASiCWithXAdESContainerExtractor(
                new FileDocument("src/test/resources/signable/open-document.odt")).extract()));
        assertFalse(factory.isSupported(new ASiCWithXAdESContainerExtractor(
                new FileDocument("src/test/resources/signable/asic_cades.zip")).extract()));
    }

    @Test
    public void isSupportedMultipleASiCContentTest() {
        ASiCWithXAdESContainerMergerFactory factory = new ASiCWithXAdESContainerMergerFactory();
        assertTrue(factory.isSupported(
                new ASiCWithXAdESContainerExtractor(new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract(),
                new ASiCWithXAdESContainerExtractor(new FileDocument("src/test/resources/validation/multifiles-ok.asics")).extract()));
        assertTrue(factory.isSupported(
                new ASiCWithXAdESContainerExtractor(new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract(),
                new ASiCWithXAdESContainerExtractor(new FileDocument("src/test/resources/validation/multifiles-ok.asics")).extract(),
                new ASiCWithXAdESContainerExtractor(new FileDocument("src/test/resources/signable/test.zip")).extract()));
        assertFalse(factory.isSupported(
                new ASiCWithXAdESContainerExtractor(new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract(),
                new ASiCWithXAdESContainerExtractor(new FileDocument("src/test/resources/signable/asic_cades.zip")).extract()));
    }

    @Test
    public void isSupportedNullTest() {
        ASiCWithXAdESContainerMergerFactory factory = new ASiCWithXAdESContainerMergerFactory();

        Exception exception = assertThrows(NullPointerException.class, () -> factory.isSupported((DSSDocument[]) null));
        assertEquals("Containers shall be provided!", exception.getMessage());
        exception = assertThrows(NullPointerException.class, () -> factory.isSupported(new DSSDocument[]{}));
        assertEquals("At least one container shall be provided!", exception.getMessage());
        exception = assertThrows(NullPointerException.class, () -> factory.isSupported((DSSDocument) null));
        assertEquals("A document cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> factory.isSupported((ASiCContent[]) null));
        assertEquals("ASiCContents shall be provided!", exception.getMessage());
        exception = assertThrows(NullPointerException.class, () -> factory.isSupported(new ASiCContent[]{}));
        assertEquals("At least one ASiCContent shall be provided!", exception.getMessage());
        exception = assertThrows(NullPointerException.class, () -> factory.isSupported((ASiCContent) null));
        assertEquals("An ASiCContent cannot be null!", exception.getMessage());
    }

    @Test
    public void createFromDSSDocumentTest() {
        ASiCWithXAdESContainerMergerFactory factory = new ASiCWithXAdESContainerMergerFactory();

        ASiCContainerMerger merger = factory.create(
                new FileDocument("src/test/resources/validation/onefile-ok.asics"));
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCSWithXAdESContainerMerger);

        merger = factory.create(
                new FileDocument("src/test/resources/validation/onefile-ok.asics"),
                new FileDocument("src/test/resources/validation/multifiles-ok.asics"));
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCSWithXAdESContainerMerger);

        merger = factory.create(
                new FileDocument("src/test/resources/validation/onefile-ok.asics"),
                new FileDocument("src/test/resources/signable/test.zip"));
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCSWithXAdESContainerMerger);

        merger = factory.create(
                new FileDocument("src/test/resources/validation/onefile-ok.asics"),
                new FileDocument("src/test/resources/validation/multifiles-ok.asics"),
                new FileDocument("src/test/resources/signable/test.zip"));
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCSWithXAdESContainerMerger);

        merger = factory.create(
                new FileDocument("src/test/resources/signable/test.zip"),
                new FileDocument("src/test/resources/validation/onefile-ok.asics"),
                new FileDocument("src/test/resources/validation/multifiles-ok.asics"));
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCSWithXAdESContainerMerger);

        merger = factory.create(
                new FileDocument("src/test/resources/validation/onefile-ok.asice"));
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCEWithXAdESContainerMerger);

        merger = factory.create(
                new FileDocument("src/test/resources/validation/onefile-ok.asice"),
                new FileDocument("src/test/resources/validation/multifiles-ok.asice"));
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCEWithXAdESContainerMerger);

        merger = factory.create(
                new FileDocument("src/test/resources/validation/onefile-ok.asice"),
                new FileDocument("src/test/resources/validation/multifiles-ok.asice"),
                new FileDocument("src/test/resources/signable/test.zip"));
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCEWithXAdESContainerMerger);

        merger = factory.create(
                new FileDocument("src/test/resources/signable/test.zip"),
                new FileDocument("src/test/resources/validation/onefile-ok.asice"),
                new FileDocument("src/test/resources/validation/multifiles-ok.asice"));
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCEWithXAdESContainerMerger);

        Exception exception = assertThrows(UnsupportedOperationException.class, () -> factory.create(
                new FileDocument("src/test/resources/validation/onefile-ok.asice"),
                new FileDocument("src/test/resources/validation/onefile-ok.asics")));
        assertEquals("Unable to create an ASiCContainerMerger for two documents of different ASiCContainer types!",
                exception.getMessage());

        exception = assertThrows(UnsupportedOperationException.class, () -> factory.create(
                new FileDocument("src/test/resources/validation/onefile-ok.asics"),
                new FileDocument("src/test/resources/signable/test.zip"),
                new FileDocument("src/test/resources/validation/onefile-ok.asice")));
        assertEquals("Unable to create an ASiCContainerMerger for two documents of different ASiCContainer types!",
                exception.getMessage());
    }

    @Test
    public void createFromASiCContainerTest() {
        ASiCWithXAdESContainerMergerFactory factory = new ASiCWithXAdESContainerMergerFactory();

        ASiCContainerMerger merger = factory.create(
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract());
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCSWithXAdESContainerMerger);

        merger = factory.create(
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract(),
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/multifiles-ok.asics")).extract());
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCSWithXAdESContainerMerger);

        merger = factory.create(
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract(),
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/signable/test.zip")).extract());
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCSWithXAdESContainerMerger);

        merger = factory.create(
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract(),
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/multifiles-ok.asics")).extract(),
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/signable/test.zip")).extract());
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCSWithXAdESContainerMerger);

        merger = factory.create(
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/signable/test.zip")).extract(),
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract(),
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/multifiles-ok.asics")).extract());
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCSWithXAdESContainerMerger);

        merger = factory.create(
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asice")).extract());
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCEWithXAdESContainerMerger);

        merger = factory.create(
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asice")).extract(),
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/multifiles-ok.asice")).extract());
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCEWithXAdESContainerMerger);

        merger = factory.create(
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asice")).extract(),
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/multifiles-ok.asice")).extract(),
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/signable/test.zip")).extract());
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCEWithXAdESContainerMerger);

        merger = factory.create(
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/signable/test.zip")).extract(),
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asice")).extract(),
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/multifiles-ok.asice")).extract());
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCEWithXAdESContainerMerger);

        Exception exception = assertThrows(UnsupportedOperationException.class, () -> factory.create(
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asice")).extract(),
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract()));
        assertEquals("Unable to create an ASiCContainerMerger for two documents of different ASiCContainer types!",
                exception.getMessage());

        exception = assertThrows(UnsupportedOperationException.class, () -> factory.create(
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract(),
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/signable/test.zip")).extract(),
                new ASiCWithXAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asice")).extract()));
        assertEquals("Unable to create an ASiCContainerMerger for two documents of different ASiCContainer types!",
                exception.getMessage());
    }

    @Test
    public void createNullTest() {
        ASiCWithXAdESContainerMergerFactory factory = new ASiCWithXAdESContainerMergerFactory();

        Exception exception = assertThrows(NullPointerException.class, () -> factory.create((DSSDocument[]) null));
        assertEquals("Containers shall be provided!", exception.getMessage());
        exception = assertThrows(NullPointerException.class, () -> factory.create(new DSSDocument[]{}));
        assertEquals("At least one container shall be provided!", exception.getMessage());
        exception = assertThrows(NullPointerException.class, () -> factory.create((DSSDocument) null));
        assertEquals("A document cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> factory.create((ASiCContent[]) null));
        assertEquals("ASiCContents shall be provided!", exception.getMessage());
        exception = assertThrows(NullPointerException.class, () -> factory.create(new ASiCContent[]{}));
        assertEquals("At least one ASiCContent shall be provided!", exception.getMessage());
        exception = assertThrows(NullPointerException.class, () -> factory.create((ASiCContent) null));
        assertEquals("An ASiCContent cannot be null!", exception.getMessage());
    }

}
