/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.asic.cades.merge;

import eu.europa.esig.dss.asic.cades.extract.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.merge.ASiCContainerMerger;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCWithCAdESContainerMergerFactoryTest {

    @Test
    public void isSupportedDSSDocumentTest() {
        ASiCWithCAdESContainerMergerFactory factory = new ASiCWithCAdESContainerMergerFactory();
        assertTrue(factory.isSupported(new FileDocument("src/test/resources/validation/onefile-ok.asics")));
        assertTrue(factory.isSupported(new FileDocument("src/test/resources/validation/multifiles-ok.asics")));
        assertTrue(factory.isSupported(new FileDocument("src/test/resources/signable/test.zip"))); // simple container
        assertTrue(factory.isSupported(new FileDocument("src/test/resources/validation/onefile-ok.asice")));
        assertTrue(factory.isSupported(new FileDocument("src/test/resources/validation/multifiles-ok.asice")));
        assertTrue(factory.isSupported(new FileDocument("src/test/resources/signable/asic_cades.zip"))); // ASiC-E
        assertFalse(factory.isSupported(new FileDocument("src/test/resources/signable/document.odt")));
        assertFalse(factory.isSupported(new FileDocument("src/test/resources/signable/asic_xades.zip")));
        assertFalse(factory.isSupported(new FileDocument("src/test/resources/signable/test.txt")));
    }

    @Test
    public void isSupportedMultipleDSSDocumentTest() {
        ASiCWithCAdESContainerMergerFactory factory = new ASiCWithCAdESContainerMergerFactory();
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
                new FileDocument("src/test/resources/signable/asic_xades.zip")));
        assertFalse(factory.isSupported(
                new FileDocument("src/test/resources/signable/test.txt"),
                new FileDocument("src/test/resources/signable/asic_xades.zip")));
    }

    @Test
    public void isSupportedASiCContentTest() {
        ASiCWithCAdESContainerMergerFactory factory = new ASiCWithCAdESContainerMergerFactory();
        assertTrue(factory.isSupported(new ASiCWithCAdESContainerExtractor(
                new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract()));
        assertTrue(factory.isSupported(new ASiCWithCAdESContainerExtractor(
                new FileDocument("src/test/resources/validation/multifiles-ok.asics")).extract()));
        assertTrue(factory.isSupported(new ASiCWithCAdESContainerExtractor(
                new FileDocument("src/test/resources/signable/test.zip")).extract()));
        assertTrue(factory.isSupported(new ASiCWithCAdESContainerExtractor(
                new FileDocument("src/test/resources/validation/onefile-ok.asice")).extract()));
        assertFalse(factory.isSupported(new ASiCWithCAdESContainerExtractor(
                new FileDocument("src/test/resources/signable/document.odt")).extract()));
        assertFalse(factory.isSupported(new ASiCWithCAdESContainerExtractor(
                new FileDocument("src/test/resources/signable/asic_xades.zip")).extract()));
    }

    @Test
    public void isSupportedMultipleASiCContentTest() {
        ASiCWithCAdESContainerMergerFactory factory = new ASiCWithCAdESContainerMergerFactory();
        assertTrue(factory.isSupported(
                new ASiCWithCAdESContainerExtractor(new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract(),
                new ASiCWithCAdESContainerExtractor(new FileDocument("src/test/resources/validation/multifiles-ok.asics")).extract()));
        assertTrue(factory.isSupported(
                new ASiCWithCAdESContainerExtractor(new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract(),
                new ASiCWithCAdESContainerExtractor(new FileDocument("src/test/resources/validation/multifiles-ok.asics")).extract(),
                new ASiCWithCAdESContainerExtractor(new FileDocument("src/test/resources/signable/test.zip")).extract()));
        assertFalse(factory.isSupported(
                new ASiCWithCAdESContainerExtractor(new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract(),
                new ASiCWithCAdESContainerExtractor(new FileDocument("src/test/resources/signable/asic_xades.zip")).extract()));
    }

    @Test
    public void isSupportedNullTest() {
        ASiCWithCAdESContainerMergerFactory factory = new ASiCWithCAdESContainerMergerFactory();

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
        ASiCWithCAdESContainerMergerFactory factory = new ASiCWithCAdESContainerMergerFactory();

        ASiCContainerMerger merger = factory.create(
                new FileDocument("src/test/resources/validation/onefile-ok.asics"));
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCSWithCAdESContainerMerger);

        merger = factory.create(
                new FileDocument("src/test/resources/validation/onefile-ok.asics"),
                new FileDocument("src/test/resources/validation/multifiles-ok.asics"));
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCSWithCAdESContainerMerger);

        merger = factory.create(
                new FileDocument("src/test/resources/validation/onefile-ok.asics"),
                new FileDocument("src/test/resources/signable/test.zip"));
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCSWithCAdESContainerMerger);

        merger = factory.create(
                new FileDocument("src/test/resources/validation/onefile-ok.asics"),
                new FileDocument("src/test/resources/validation/multifiles-ok.asics"),
                new FileDocument("src/test/resources/signable/test.zip"));
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCSWithCAdESContainerMerger);

        merger = factory.create(
                new FileDocument("src/test/resources/signable/test.zip"),
                new FileDocument("src/test/resources/validation/onefile-ok.asics"),
                new FileDocument("src/test/resources/validation/multifiles-ok.asics"));
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCSWithCAdESContainerMerger);

        merger = factory.create(
                new FileDocument("src/test/resources/validation/onefile-ok.asice"));
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCEWithCAdESContainerMerger);

        merger = factory.create(
                new FileDocument("src/test/resources/validation/onefile-ok.asice"),
                new FileDocument("src/test/resources/validation/multifiles-ok.asice"));
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCEWithCAdESContainerMerger);

        merger = factory.create(
                new FileDocument("src/test/resources/validation/onefile-ok.asice"),
                new FileDocument("src/test/resources/validation/multifiles-ok.asice"),
                new FileDocument("src/test/resources/signable/test.zip"));
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCEWithCAdESContainerMerger);

        merger = factory.create(
                new FileDocument("src/test/resources/signable/test.zip"),
                new FileDocument("src/test/resources/validation/onefile-ok.asice"),
                new FileDocument("src/test/resources/validation/multifiles-ok.asice"));
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCEWithCAdESContainerMerger);

        Exception exception = assertThrows(UnsupportedOperationException.class, () -> factory.create(
                new FileDocument("src/test/resources/validation/onefile-ok.asice"),
                new FileDocument("src/test/resources/validation/onefile-ok.asics")));
        assertEquals("Unable to create an ASiCContainerMerger for documents of different ASiCContainer types!",
                exception.getMessage());

        exception = assertThrows(UnsupportedOperationException.class, () -> factory.create(
                new FileDocument("src/test/resources/validation/onefile-ok.asics"),
                new FileDocument("src/test/resources/signable/test.zip"),
                new FileDocument("src/test/resources/validation/onefile-ok.asice")));
        assertEquals("Unable to create an ASiCContainerMerger for documents of different ASiCContainer types!",
                exception.getMessage());
    }

    @Test
    public void createFromASiCContainerTest() {
        ASiCWithCAdESContainerMergerFactory factory = new ASiCWithCAdESContainerMergerFactory();

        ASiCContainerMerger merger = factory.create(
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract());
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCSWithCAdESContainerMerger);

        merger = factory.create(
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract(),
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/multifiles-ok.asics")).extract());
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCSWithCAdESContainerMerger);

        merger = factory.create(
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract(),
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/signable/test.zip")).extract());
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCSWithCAdESContainerMerger);

        merger = factory.create(
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract(),
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/multifiles-ok.asics")).extract(),
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/signable/test.zip")).extract());
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCSWithCAdESContainerMerger);

        merger = factory.create(
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/signable/test.zip")).extract(),
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract(),
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/multifiles-ok.asics")).extract());
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCSWithCAdESContainerMerger);

        merger = factory.create(
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asice")).extract());
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCEWithCAdESContainerMerger);

        merger = factory.create(
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asice")).extract(),
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/multifiles-ok.asice")).extract());
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCEWithCAdESContainerMerger);

        merger = factory.create(
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asice")).extract(),
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/multifiles-ok.asice")).extract(),
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/signable/test.zip")).extract());
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCEWithCAdESContainerMerger);

        merger = factory.create(
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/signable/test.zip")).extract(),
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asice")).extract(),
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/multifiles-ok.asice")).extract());
        assertNotNull(merger);
        assertTrue(merger instanceof ASiCEWithCAdESContainerMerger);

        Exception exception = assertThrows(UnsupportedOperationException.class, () -> factory.create(
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asice")).extract(),
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract()));
        assertEquals("Unable to create an ASiCContainerMerger for documents of different ASiCContainer types!",
                exception.getMessage());

        exception = assertThrows(UnsupportedOperationException.class, () -> factory.create(
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asics")).extract(),
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/signable/test.zip")).extract(),
                new ASiCWithCAdESContainerExtractor(
                        new FileDocument("src/test/resources/validation/onefile-ok.asice")).extract()));
        assertEquals("Unable to create an ASiCContainerMerger for documents of different ASiCContainer types!",
                exception.getMessage());
    }

    @Test
    public void createNullTest() {
        ASiCWithCAdESContainerMergerFactory factory = new ASiCWithCAdESContainerMergerFactory();

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
