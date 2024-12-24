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
package eu.europa.esig.dss.asic.common.evidencerecord;

import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.asn1.digest.ASN1EvidenceRecordDataObjectDigestBuilder;
import eu.europa.esig.dss.evidencerecord.asn1.digest.ASN1EvidenceRecordDataObjectDigestBuilderFactory;
import eu.europa.esig.dss.evidencerecord.xml.digest.XMLEvidenceRecordDataObjectDigestBuilder;
import eu.europa.esig.dss.evidencerecord.xml.digest.XMLEvidenceRecordDataObjectDigestBuilderFactory;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.FileDocument;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ZipContentEvidenceRecordDigestBuilderTest {

    private static DSSDocument zipContainer;

    @BeforeAll
    static void init() {
        zipContainer = new FileDocument("src/test/resources/multifiles-ok.asice");
    }

    @Test
    void testXMLERS() {
        ZipContentEvidenceRecordDigestBuilder zipContentEvidenceRecordDigestBuilder = new ZipContentEvidenceRecordDigestBuilder(zipContainer);
        Exception exception = assertThrows(NullPointerException.class, zipContentEvidenceRecordDigestBuilder::buildDigestGroup);
        assertEquals("DataObjectDigestBuilderFactory shall be set to continue! Please choose the corresponding " +
                "implementation for your evidence record type (e.g. XMLERS or ASN.1).", exception.getMessage());

        XMLEvidenceRecordDataObjectDigestBuilderFactory xmlEvidenceRecordDataObjectDigestBuilderFactory = new XMLEvidenceRecordDataObjectDigestBuilderFactory();
        zipContentEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(xmlEvidenceRecordDataObjectDigestBuilderFactory);

        List<Digest> digests = zipContentEvidenceRecordDigestBuilder.buildDigestGroup();
        assertEquals(6, digests.size());
        for (Digest digest : digests) {
            assertEquals(DigestAlgorithm.SHA256, digest.getAlgorithm());
            assertNotNull(digest.getValue());
        }

        List<DSSDocument> containerDocuments = ZipUtils.getInstance().extractContainerContent(zipContainer);
        assertEquals(6, containerDocuments.size());
        for (DSSDocument document : containerDocuments) {
            XMLEvidenceRecordDataObjectDigestBuilder xmlEvidenceRecordDataObjectDigestBuilder =
                    new XMLEvidenceRecordDataObjectDigestBuilder(document);
            Digest xmlDigest = xmlEvidenceRecordDataObjectDigestBuilder.build();
            assertTrue(digests.contains(xmlDigest));
        }

        xmlEvidenceRecordDataObjectDigestBuilderFactory.setCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);
        List<Digest> exclusiveCanonDigests = zipContentEvidenceRecordDigestBuilder.buildDigestGroup();
        assertEquals(6, exclusiveCanonDigests.size());

        for (DSSDocument document : containerDocuments) {
            XMLEvidenceRecordDataObjectDigestBuilder xmlEvidenceRecordDataObjectDigestBuilder =
                    new XMLEvidenceRecordDataObjectDigestBuilder(document)
                            .setCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);
            Digest xmlDigest = xmlEvidenceRecordDataObjectDigestBuilder.build();
            assertTrue(exclusiveCanonDigests.contains(xmlDigest));
        }

        zipContentEvidenceRecordDigestBuilder = new ZipContentEvidenceRecordDigestBuilder(zipContainer, DigestAlgorithm.SHA512);
        zipContentEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(xmlEvidenceRecordDataObjectDigestBuilderFactory);

        digests = zipContentEvidenceRecordDigestBuilder.buildDigestGroup();
        assertEquals(6, digests.size());
        for (Digest digest : digests) {
            assertEquals(DigestAlgorithm.SHA512, digest.getAlgorithm());
            assertNotNull(digest.getValue());
        }

        containerDocuments = ZipUtils.getInstance().extractContainerContent(zipContainer);
        assertEquals(6, containerDocuments.size());
        for (DSSDocument document : containerDocuments) {
            XMLEvidenceRecordDataObjectDigestBuilder xmlEvidenceRecordDataObjectDigestBuilder =
                    new XMLEvidenceRecordDataObjectDigestBuilder(document, DigestAlgorithm.SHA512);
            Digest xmlDigest = xmlEvidenceRecordDataObjectDigestBuilder.build();
            assertTrue(digests.contains(xmlDigest));
        }
    }

    @Test
    void testERS() {
        ZipContentEvidenceRecordDigestBuilder zipContentEvidenceRecordDigestBuilder = new ZipContentEvidenceRecordDigestBuilder(zipContainer);

        ASN1EvidenceRecordDataObjectDigestBuilderFactory asn1EvidenceRecordDataObjectDigestBuilderFactory = new ASN1EvidenceRecordDataObjectDigestBuilderFactory();
        zipContentEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(asn1EvidenceRecordDataObjectDigestBuilderFactory);

        List<Digest> digests = zipContentEvidenceRecordDigestBuilder.buildDigestGroup();
        assertEquals(6, digests.size());
        for (Digest digest : digests) {
            assertEquals(DigestAlgorithm.SHA256, digest.getAlgorithm());
            assertNotNull(digest.getValue());
        }

        List<DSSDocument> containerDocuments = ZipUtils.getInstance().extractContainerContent(zipContainer);
        assertEquals(6, containerDocuments.size());
        for (DSSDocument document : containerDocuments) {
            ASN1EvidenceRecordDataObjectDigestBuilder asn1EvidenceRecordDataObjectDigestBuilder =
                    new ASN1EvidenceRecordDataObjectDigestBuilder(document);
            Digest asn1Digest = asn1EvidenceRecordDataObjectDigestBuilder.build();
            assertTrue(digests.contains(asn1Digest));
        }

        zipContentEvidenceRecordDigestBuilder = new ZipContentEvidenceRecordDigestBuilder(zipContainer, DigestAlgorithm.SHA512);
        zipContentEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(asn1EvidenceRecordDataObjectDigestBuilderFactory);

        digests = zipContentEvidenceRecordDigestBuilder.buildDigestGroup();
        assertEquals(6, digests.size());
        for (Digest digest : digests) {
            assertEquals(DigestAlgorithm.SHA512, digest.getAlgorithm());
            assertNotNull(digest.getValue());
        }

        containerDocuments = ZipUtils.getInstance().extractContainerContent(zipContainer);
        assertEquals(6, containerDocuments.size());
        for (DSSDocument document : containerDocuments) {
            ASN1EvidenceRecordDataObjectDigestBuilder asn1EvidenceRecordDataObjectDigestBuilder =
                    new ASN1EvidenceRecordDataObjectDigestBuilder(document, DigestAlgorithm.SHA512);
            Digest asn1Digest = asn1EvidenceRecordDataObjectDigestBuilder.build();
            assertTrue(digests.contains(asn1Digest));
        }
    }

}
