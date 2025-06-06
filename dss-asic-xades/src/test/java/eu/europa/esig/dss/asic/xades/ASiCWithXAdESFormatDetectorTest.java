/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.asic.xades;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCWithXAdESFormatDetectorTest {

    @Test
    void isSupportedZip() {
        final ASiCWithXAdESFormatDetector asicDetector = new ASiCWithXAdESFormatDetector();

        byte[] wrongBytes = new byte[] { 1, 2 };
        assertFalse(asicDetector.isSupportedZip(new InMemoryDocument(wrongBytes)));
        assertFalse(asicDetector.isSupportedZip(new InMemoryDocument(wrongBytes, "test", MimeTypeEnum.PDF)));
        assertFalse(asicDetector.isSupportedZip(new InMemoryDocument(wrongBytes, "test")));
        assertFalse(asicDetector.isSupportedZip(new InMemoryDocument(wrongBytes, "test", MimeTypeEnum.XML)));
        assertFalse(asicDetector.isSupportedZip(new InMemoryDocument(wrongBytes, "test.xml")));

        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/validation/onefile-ok.asice")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/validation/onefile-ok.asics")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/validation/multifiles-ok.asice")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/validation/multifiles-ok.asics")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/validation/libreoffice.ods")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/validation/libreoffice.odt")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/validation/open-document-signed.odt")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/validation/open-document-resigned.odt")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/validation/evidencerecord/xades-lt-with-er.sce")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/validation/evidencerecord/xades-lta-with-er-hashtree.scs")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/validation/evidencerecord/xades-lta-with-er-hashtree.sce")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/validation/evidencerecord/er-one-file.scs")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/validation/evidencerecord/er-multi-files.sce")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/signable/asic_xades.zip")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/signable/test.zip")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/signable/empty.zip")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/ASiCEWith2Signatures.bdoc")));

        assertFalse(asicDetector.isSupportedZip(new FileDocument("src/test/resources/bdoc-spec21.pdf")));
        assertFalse(asicDetector.isSupportedZip(new FileDocument("src/test/resources/manifest-sample.xml")));
        assertFalse(asicDetector.isSupportedZip(new FileDocument("src/test/resources/signable/test.txt")));
        assertFalse(asicDetector.isSupportedZip(new FileDocument("src/test/resources/signable/asic_cades.zip")));
        assertFalse(asicDetector.isSupportedZip(new FileDocument("src/test/resources/signable/asic_cades_er.sce")));
    }

    @Test
    void isSupportedASiC() {
        final ASiCWithXAdESFormatDetector asicDetector = new ASiCWithXAdESFormatDetector();

        byte[] wrongBytes = new byte[] { 1, 2 };
        assertFalse(asicDetector.isSupportedASiC(new InMemoryDocument(wrongBytes)));
        assertFalse(asicDetector.isSupportedASiC(new InMemoryDocument(wrongBytes, "test", MimeTypeEnum.PDF)));
        assertFalse(asicDetector.isSupportedASiC(new InMemoryDocument(wrongBytes, "test")));
        assertFalse(asicDetector.isSupportedASiC(new InMemoryDocument(wrongBytes, "test", MimeTypeEnum.XML)));
        assertFalse(asicDetector.isSupportedASiC(new InMemoryDocument(wrongBytes, "test.xml")));

        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/validation/onefile-ok.asice")));
        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/validation/onefile-ok.asics")));
        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/validation/multifiles-ok.asice")));
        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/validation/multifiles-ok.asics")));
        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/validation/libreoffice.ods")));
        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/validation/libreoffice.odt")));
        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/validation/open-document-signed.odt")));
        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/validation/open-document-resigned.odt")));
        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/validation/evidencerecord/xades-lt-with-er.sce")));
        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/validation/evidencerecord/xades-lta-with-er-hashtree.scs")));
        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/validation/evidencerecord/xades-lta-with-er-hashtree.sce")));
        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/validation/evidencerecord/er-one-file.scs")));
        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/validation/evidencerecord/er-multi-files.sce")));
        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/signable/asic_xades.zip")));
        assertFalse(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/signable/test.zip")));
        assertFalse(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/signable/empty.zip")));
        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/ASiCEWith2Signatures.bdoc")));

        assertFalse(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/bdoc-spec21.pdf")));
        assertFalse(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/manifest-sample.xml")));
        assertFalse(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/signable/test.txt")));
        assertFalse(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/signable/asic_cades.zip")));
        assertFalse(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/signable/asic_cades_er.sce")));
    }
    
}
