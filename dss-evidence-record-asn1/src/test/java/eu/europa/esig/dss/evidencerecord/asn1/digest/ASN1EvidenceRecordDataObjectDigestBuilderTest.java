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
package eu.europa.esig.dss.evidencerecord.asn1.digest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ASN1EvidenceRecordDataObjectDigestBuilderTest {

    @Test
    void testBinaryData() {
        byte[] data = "Hello world!".getBytes(StandardCharsets.UTF_8);

        assertEquals("C0535E4BE2B79FFD93291305436BF889314E4A3FAEC05ECFFCBB7DF31AD9E51A",
                new ASN1EvidenceRecordDataObjectDigestBuilder(data).build().getHexValue());
        assertEquals("D3486AE9136E7856BC42212385EA797094475802",
                new ASN1EvidenceRecordDataObjectDigestBuilder(data, DigestAlgorithm.SHA1).build().getHexValue());
        assertEquals("7E81EBE9E604A0C97FEF0E4CFE71F9BA0ECBA13332BDE953AD1C66E4",
                new ASN1EvidenceRecordDataObjectDigestBuilder(data, DigestAlgorithm.SHA224).build().getHexValue());
        assertEquals("C0535E4BE2B79FFD93291305436BF889314E4A3FAEC05ECFFCBB7DF31AD9E51A",
                new ASN1EvidenceRecordDataObjectDigestBuilder(data, DigestAlgorithm.SHA256).build().getHexValue());
        assertEquals("F6CDE2A0F819314CDDE55FC227D8D7DAE3D28CC556222A0A8AD66D91CCAD4AAD6094F517A2182360C9AACF6A3DC323162CB6FD8CDFFEDB0FE038F55E85FFB5B6",
                new ASN1EvidenceRecordDataObjectDigestBuilder(data, DigestAlgorithm.SHA512).build().getHexValue());
        assertEquals("C0535E4BE2B79FFD93291305436BF889314E4A3FAEC05ECFFCBB7DF31AD9E51A",
                new ASN1EvidenceRecordDataObjectDigestBuilder(new InMemoryDocument(data), DigestAlgorithm.SHA256).build().getHexValue());
        assertEquals("C0535E4BE2B79FFD93291305436BF889314E4A3FAEC05ECFFCBB7DF31AD9E51A",
                new ASN1EvidenceRecordDataObjectDigestBuilder(new InMemoryDocument(data).openStream(), DigestAlgorithm.SHA256).build().getHexValue());
    }

    @Test
    void testDocument() {
        DSSDocument document = new FileDocument("src/test/resources/BIN-1.bin");

        assertEquals("A1D4E7B50D9693F9A31B2E9484EA6ADFA585837730FE2BA94D13A5D4C81C32DF",
                new ASN1EvidenceRecordDataObjectDigestBuilder(document).build().getHexValue());
        assertEquals("8F2112977E1AAA4FBDC86C199A8C571FE8C7E9E3",
                new ASN1EvidenceRecordDataObjectDigestBuilder(document, DigestAlgorithm.SHA1).build().getHexValue());
        assertEquals("A1D4E7B50D9693F9A31B2E9484EA6ADFA585837730FE2BA94D13A5D4C81C32DF",
                new ASN1EvidenceRecordDataObjectDigestBuilder(document, DigestAlgorithm.SHA256).build().getHexValue());
        assertEquals("A327815CC2087226095CFE86B1454F9EF0C62307DA1E4D1491A6F1CC931DACE8DD97376DFCE9816872452552404490C4EEB9635B4B76064727E95C7E8C867796",
                new ASN1EvidenceRecordDataObjectDigestBuilder(document, DigestAlgorithm.SHA512).build().getHexValue());

        assertEquals("A1D4E7B50D9693F9A31B2E9484EA6ADFA585837730FE2BA94D13A5D4C81C32DF",
                new ASN1EvidenceRecordDataObjectDigestBuilder(DSSUtils.toByteArray(document)).build().getHexValue());
        assertEquals("A1D4E7B50D9693F9A31B2E9484EA6ADFA585837730FE2BA94D13A5D4C81C32DF",
                new ASN1EvidenceRecordDataObjectDigestBuilder(document.openStream()).build().getHexValue());
    }

    @Test
    void nullTest() {
        Exception exception = assertThrows(NullPointerException.class,
                () -> new ASN1EvidenceRecordDataObjectDigestBuilder((byte[]) null));
        assertEquals("Bytes cannot be null", exception.getMessage());

        exception = assertThrows(NullPointerException.class,
                () -> new ASN1EvidenceRecordDataObjectDigestBuilder((InputStream) null));
        assertEquals("InputStream cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class,
                () -> new ASN1EvidenceRecordDataObjectDigestBuilder((DSSDocument) null));
        assertEquals("Document cannot be null!", exception.getMessage());

        byte[] data = "Hello world!".getBytes(StandardCharsets.UTF_8);

        exception = assertThrows(NullPointerException.class,
                () -> new ASN1EvidenceRecordDataObjectDigestBuilder(data, null));
        assertEquals("DigestAlgorithm cannot be null!", exception.getMessage());
    }

}
