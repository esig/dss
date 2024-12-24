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
package eu.europa.esig.dss.evidencerecord.xml.digest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class XMLEvidenceRecordDataObjectDigestBuilderTest {

    @Test
    void testBinaryData() {
        byte[] data = "Hello world!".getBytes(StandardCharsets.UTF_8);

        assertEquals("C0535E4BE2B79FFD93291305436BF889314E4A3FAEC05ECFFCBB7DF31AD9E51A",
                new XMLEvidenceRecordDataObjectDigestBuilder(data).build().getHexValue());
        assertEquals("D3486AE9136E7856BC42212385EA797094475802",
                new XMLEvidenceRecordDataObjectDigestBuilder(data, DigestAlgorithm.SHA1).build().getHexValue());
        assertEquals("7E81EBE9E604A0C97FEF0E4CFE71F9BA0ECBA13332BDE953AD1C66E4",
                new XMLEvidenceRecordDataObjectDigestBuilder(data, DigestAlgorithm.SHA224).build().getHexValue());
        assertEquals("C0535E4BE2B79FFD93291305436BF889314E4A3FAEC05ECFFCBB7DF31AD9E51A",
                new XMLEvidenceRecordDataObjectDigestBuilder(data, DigestAlgorithm.SHA256).build().getHexValue());
        assertEquals("F6CDE2A0F819314CDDE55FC227D8D7DAE3D28CC556222A0A8AD66D91CCAD4AAD6094F517A2182360C9AACF6A3DC323162CB6FD8CDFFEDB0FE038F55E85FFB5B6",
                new XMLEvidenceRecordDataObjectDigestBuilder(data, DigestAlgorithm.SHA512).build().getHexValue());
        assertEquals("C0535E4BE2B79FFD93291305436BF889314E4A3FAEC05ECFFCBB7DF31AD9E51A",

                new XMLEvidenceRecordDataObjectDigestBuilder(data, DigestAlgorithm.SHA256)
                        .setCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE).build().getHexValue());
        assertEquals("C0535E4BE2B79FFD93291305436BF889314E4A3FAEC05ECFFCBB7DF31AD9E51A",
                new XMLEvidenceRecordDataObjectDigestBuilder(data, DigestAlgorithm.SHA256)
                        .setCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS).build().getHexValue());
        assertEquals("C0535E4BE2B79FFD93291305436BF889314E4A3FAEC05ECFFCBB7DF31AD9E51A",

                new XMLEvidenceRecordDataObjectDigestBuilder(new InMemoryDocument(data), DigestAlgorithm.SHA256).build().getHexValue());
        assertEquals("C0535E4BE2B79FFD93291305436BF889314E4A3FAEC05ECFFCBB7DF31AD9E51A",
                new XMLEvidenceRecordDataObjectDigestBuilder(new InMemoryDocument(data).openStream(), DigestAlgorithm.SHA256).build().getHexValue());
    }

    @Test
    void testXmlDocument() {
        DSSDocument document = new FileDocument("src/test/resources/sample-c14n.xml");

        assertEquals("/TiBXkCOtm0bSdOukpXHtqSu6G5EPRfwyYH9DJ9YtCE=",
                Utils.toBase64(new XMLEvidenceRecordDataObjectDigestBuilder(document).build().getValue()));
        assertEquals("Rn+AFbDoNOGt6CM7SCrfeZJq/PU=",
                Utils.toBase64(new XMLEvidenceRecordDataObjectDigestBuilder(document, DigestAlgorithm.SHA1).build().getValue()));
        assertEquals("/TiBXkCOtm0bSdOukpXHtqSu6G5EPRfwyYH9DJ9YtCE=",
                Utils.toBase64(new XMLEvidenceRecordDataObjectDigestBuilder(document, DigestAlgorithm.SHA256).build().getValue()));
        assertEquals("m5PJAJpfXjJB2KHyZaVkgX/QCM3CrBGX/AeXZY985k337ZOjHr7rxyE6mY+TFy/vk6AOa1DoYRyg/yJCRDcFlQ==",
                Utils.toBase64(new XMLEvidenceRecordDataObjectDigestBuilder(document, DigestAlgorithm.SHA512).build().getValue()));

        assertEquals("/TiBXkCOtm0bSdOukpXHtqSu6G5EPRfwyYH9DJ9YtCE=",
                Utils.toBase64(new XMLEvidenceRecordDataObjectDigestBuilder(document, DigestAlgorithm.SHA256)
                        .setCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE).build().getValue()));
        assertEquals("0VrRKOvUCLDg3QSMAzIrdahAmiCo/AFTFAjd5FZDx+0=",
                Utils.toBase64(new XMLEvidenceRecordDataObjectDigestBuilder(document, DigestAlgorithm.SHA256)
                        .setCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS).build().getValue()));

        assertEquals("/TiBXkCOtm0bSdOukpXHtqSu6G5EPRfwyYH9DJ9YtCE=",
                Utils.toBase64(new XMLEvidenceRecordDataObjectDigestBuilder(DSSUtils.toByteArray(document)).build().getValue()));
        assertEquals("/TiBXkCOtm0bSdOukpXHtqSu6G5EPRfwyYH9DJ9YtCE=",
                Utils.toBase64(new XMLEvidenceRecordDataObjectDigestBuilder(document.openStream()).build().getValue()));
    }

    @Test
    void nullTest() {
        Exception exception = assertThrows(NullPointerException.class,
                () -> new XMLEvidenceRecordDataObjectDigestBuilder((byte[]) null));
        assertEquals("Bytes cannot be null", exception.getMessage());

        exception = assertThrows(NullPointerException.class,
                () -> new XMLEvidenceRecordDataObjectDigestBuilder((InputStream) null));
        assertEquals("InputStream cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class,
                () -> new XMLEvidenceRecordDataObjectDigestBuilder((DSSDocument) null));
        assertEquals("Document cannot be null!", exception.getMessage());

        byte[] data = "Hello world!".getBytes(StandardCharsets.UTF_8);

        exception = assertThrows(NullPointerException.class,
                () -> new XMLEvidenceRecordDataObjectDigestBuilder(data, null));
        assertEquals("DigestAlgorithm cannot be null!", exception.getMessage());

        assertEquals("C0535E4BE2B79FFD93291305436BF889314E4A3FAEC05ECFFCBB7DF31AD9E51A",
                new XMLEvidenceRecordDataObjectDigestBuilder(data, DigestAlgorithm.SHA256).build().getHexValue());
    }

}
