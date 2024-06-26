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
package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilter;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilterFactory;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordDigestBuilder;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordManifestBuilder;
import eu.europa.esig.dss.asic.xades.signature.SimpleASiCWithXAdESFilenameFactory;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.xml.digest.XMLEvidenceRecordDataObjectDigestBuilderFactory;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.Test;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class ERDataObjectBuilderForASiCTest {

    @Test
    public void test() throws Exception {
        ASiCContent asicContent = new ASiCContent();
        asicContent.setSignedDocuments(Arrays.asList(
                new InMemoryDocument("Hello".getBytes(), "hello.txt"),
                new InMemoryDocument("Bye".getBytes(), "bye.txt")
        ));

        DSSDocument asicContainer = ZipUtils.getInstance().createZipArchive(asicContent);

        // tag::asic-er[]
        // import eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilter;
        // import eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilterFactory;
        // import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordDigestBuilder;
        // import eu.europa.esig.dss.evidencerecord.xml.digest.XMLEvidenceRecordDataObjectDigestBuilderFactory;
        // import eu.europa.esig.dss.model.Digest;
        // import javax.xml.crypto.dsig.CanonicalizationMethod;

        // Initialize ASiCEvidenceRecordDigestBuilder to build digest for an ASiC container
        ASiCEvidenceRecordDigestBuilder asicEvidenceRecordDigestBuilder =
                new ASiCEvidenceRecordDigestBuilder(asicContainer, DigestAlgorithm.SHA256);

        // Create an EvidenceRecordDataObjectDigestBuilderFactory corresponding to
        // the target evidence record type (example below is for XMLERS format).
        // The following implementations can be used:
        // - XMLERS RFC 6253 evidence record : {@code eu.europa.esig.dss.evidencerecord.xml.digest.XMLEvidenceRecordDataObjectDigestBuilderFactory}
        // - ERS RFC 4998 evidecnce records : {@code eu.europa.esig.dss.evidencerecord.asn1.digest.ASN1EvidenceRecordDataObjectDigestBuilderFactory}
        XMLEvidenceRecordDataObjectDigestBuilderFactory xmlEvidenceRecordDataObjectDigestBuilderFactory =
                new XMLEvidenceRecordDataObjectDigestBuilderFactory()
                        .setCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE);
        asicEvidenceRecordDigestBuilder.setDataObjectDigestBuilderFactory(xmlEvidenceRecordDataObjectDigestBuilderFactory);

        // Define an {@code eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilter}
        // in order to configure the document types to be covered by an evidence record
        // Hint : use {@code eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilterFactory}
        // in order to create a pre-configured object
        // E.g. {@code ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter()} will return
        // only original signed documents
        ASiCContentDocumentFilter asicContentDocumentFilter = ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter();
        asicEvidenceRecordDigestBuilder.setAsicContentDocumentFilter(asicContentDocumentFilter);

        // Build digest for the ASiC container's content
        List<Digest> digests = asicEvidenceRecordDigestBuilder.buildDigestGroup();
        // end::asic-er[]

        assertEquals(2, digests.size());

        DSSDocument evidenceRecordDocument = createEvidenceRecord();
        String targetEvidenceRecordFilename = evidenceRecordDocument.getName();

        // tag::asic-er-manifest[]
        // import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordManifestBuilder;
        // import eu.europa.esig.dss.asic.xades.signature.SimpleASiCWithXAdESFilenameFactory;
        // import eu.europa.esig.dss.enumerations.DigestAlgorithm;
        // import eu.europa.esig.dss.model.DSSDocument;

        // Instantiate ASiCEvidenceRecordManifestBuilder to create an ASiCEvidenceRecordManifest*.xml
        // document for the corresponding evidence record document, to be incorporated within
        // an ASiC container.
        // The constructor takes as parameters:
        // - original ASiC container document;
        // - the digest algorithm to be used on digest computation
        // - the filename of the corresponding evidence record document, to create the manifest for
        ASiCEvidenceRecordManifestBuilder evidenceRecordManifestBuilder =
                new ASiCEvidenceRecordManifestBuilder(asicContainer, DigestAlgorithm.SHA256,
                        targetEvidenceRecordFilename);

        // Provide an ASiCContentDocumentFilter defining types of documents, present within
        // the container, to be referenced from the manifest
        // Hint : Use the same ASiCContentDocumentFilter as the one used on digest computation
        // for an evidence record
        evidenceRecordManifestBuilder.setAsicContentDocumentFilter(asicContentDocumentFilter);

        // Optional : define an ASiCEvidenceRecordFilenameFactory used to build
        // a valid filename for a new ASiC Evidence Record manifest
        // Note : when not set, a final DSSDocument will be produced with a filename set to NULL
        evidenceRecordManifestBuilder.setEvidenceRecordFilenameFactory(new SimpleASiCWithXAdESFilenameFactory());

        // Create the manifest
        DSSDocument evidenceRecordManifest = evidenceRecordManifestBuilder.build();
        // end::asic-er-manifest[]

        assertNotNull(evidenceRecordManifest);

    }

    private DSSDocument createEvidenceRecord() {
        // returns dummy ER
        return new InMemoryDocument("erContent".getBytes(), "evidencerecord.xml");
    }

}
