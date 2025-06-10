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
package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PdfByteRangeDocumentTest {

    private static DSSDocument pdfDocument;
    private static ByteRange byteRange;
    private static ByteRange signatureValueByteRange;

    @BeforeAll
    static void init() {
        pdfDocument = new FileDocument("src/test/resources/validation/PAdES-LT.pdf");
        byteRange = new ByteRange(new int[]{0, 92856, 111802, 50376});
        signatureValueByteRange = new ByteRange(new int[] { 92857, 18944, 111801, 0 });
    }

    @Test
    void contentComparisonTest() {
        PdfByteRangeDocument pdfRevisionDocument = new PdfByteRangeDocument(pdfDocument, byteRange);
        assertEquals("tlP+GBlImCLCAZGWWWTLmiHtZVVTqHeiRq+ddk5hV+M=", Utils.toBase64(pdfRevisionDocument.getDigestValue(DigestAlgorithm.SHA256)));
    }

    @Test
    void readByByteTest() throws IOException, NoSuchAlgorithmException {
        PdfByteRangeDocument pdfRevisionDocument = new PdfByteRangeDocument(pdfDocument, byteRange);
        MessageDigest messageDigest = DigestAlgorithm.SHA256.getMessageDigest();
        try (InputStream is = pdfRevisionDocument.openStream();) {
            int b;
            while ((b = is.read()) != -1) {
                messageDigest.update((byte) b);
            }
            final byte[] digestBytes = messageDigest.digest();
            assertEquals("tlP+GBlImCLCAZGWWWTLmiHtZVVTqHeiRq+ddk5hV+M=", Utils.toBase64(digestBytes));
        }
    }

    @Test
    void readWithBufferArrayTest() throws IOException, NoSuchAlgorithmException {
        PdfByteRangeDocument pdfRevisionDocument = new PdfByteRangeDocument(pdfDocument, byteRange);
        MessageDigest messageDigest = DigestAlgorithm.SHA256.getMessageDigest();
        try (InputStream is = pdfRevisionDocument.openStream()) {
            final byte[] buffer = new byte[2048];
            int count;
            while ((count = is.read(buffer, 0, buffer.length)) > 0) {
                messageDigest.update(buffer, 0, count);
            }
            final byte[] digestBytes = messageDigest.digest();
            assertEquals("tlP+GBlImCLCAZGWWWTLmiHtZVVTqHeiRq+ddk5hV+M=", Utils.toBase64(digestBytes));
        }
    }

    @Test
    void closeTest() throws IOException {
        PdfByteRangeDocument pdfRevisionDocument = new PdfByteRangeDocument(pdfDocument, byteRange);
        try (InputStream is = pdfRevisionDocument.openStream()) {
            is.close();

            Exception exception = assertThrows(DSSException.class, () -> DSSUtils.toByteArray(is));
            assertEquals("Unable to read InputStream : Stream Closed", exception.getMessage());
        }
    }

    @Test
    void readDocumentInsideOpenStreamTest() throws IOException {
        PdfByteRangeDocument pdfRevisionDocument = new PdfByteRangeDocument(pdfDocument, byteRange);
        try (InputStream is = pdfRevisionDocument.openStream()) {
            assertArrayEquals(pdfRevisionDocument.getDigestValue(DigestAlgorithm.SHA256), DSSUtils.digest(DigestAlgorithm.SHA256, is));
        }
    }

    @Test
    void extractSignatureValueTest() throws IOException {
        PdfByteRangeDocument pdfCmsRevisionDocument = new PdfByteRangeDocument(pdfDocument, signatureValueByteRange);
        byte[] bytes = DSSUtils.toByteArray(pdfCmsRevisionDocument);
        assertTrue(Utils.isArrayNotEmpty(bytes));
        String str = new String(bytes);
        assertTrue(Utils.isHexEncoded(str));
        CMSSignedData cmsSignedData = DSSUtils.toCMSSignedData(Utils.fromHex(str));
        assertNotNull(cmsSignedData);

        try (InputStream is = pdfCmsRevisionDocument.openStream();
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            int b;
            while ((b = is.read()) != -1) {
                baos.write((byte) b);
            }
            assertArrayEquals(bytes, baos.toByteArray());
        }

        try (InputStream is = pdfCmsRevisionDocument.openStream();
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            final byte[] buffer = new byte[2048];
            int count;
            while ((count = is.read(buffer, 0, buffer.length)) > 0) {
                baos.write(buffer, 0, count);
            }
            assertArrayEquals(bytes, baos.toByteArray());
        }
    }

    @Test
    void persistenceTest() {
        final Set<DSSDocument> hashSet = new HashSet<>();

        DSSDocument document = getPersistenceTestDocument();
        hashSet.add(document);
        assertTrue(hashSet.contains(document));

        Digest digest = document.getDigest(DigestAlgorithm.SHA256);
        assertNotNull(digest);

        assertTrue(hashSet.contains(document));
        assertTrue(hashSet.contains(getPersistenceTestDocument()));

        for (DSSDocument altDocument : getPersistenceTestAlternativeDocuments()) {
            assertFalse(hashSet.contains(altDocument));
        }
    }

    private DSSDocument getPersistenceTestDocument() {
        return new PdfByteRangeDocument(pdfDocument, byteRange);
    }

    private List<DSSDocument> getPersistenceTestAlternativeDocuments() {
        return Arrays.asList(
                new PdfByteRangeDocument(pdfDocument, signatureValueByteRange),
                new PdfByteRangeDocument(new FileDocument("src/test/resources/doc.pdf"), byteRange),
                new PdfByteRangeDocument(new FileDocument("src/test/resources/doc.pdf"), signatureValueByteRange)
        );
    }

}
