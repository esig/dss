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
package eu.europa.esig.dss.asic.cades.preservation.container.manifest;

import eu.europa.esig.dss.asic.cades.preservation.container.ASiCEWithCAdESAddContainerASN1EvidenceRecordMultipleFilesTest;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordManifestBuilder;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.util.Arrays;
import java.util.List;

class ASiCEWithCAdESAddContainerASN1EvidenceRecordMultipleFilesCustomManifestTest extends ASiCEWithCAdESAddContainerASN1EvidenceRecordMultipleFilesTest {

    @Override
    protected List<DSSDocument> getDocumentsToPreserve() {
        return Arrays.asList(
                new InMemoryDocument("Test 12345".getBytes(), "text1"),
                new InMemoryDocument("Test 67890".getBytes(), "text2")
        );
    }

    @Override
    protected DSSDocument getASiCEvidenceRecordManifest() {
        ASiCContent asicContent = new ASiCContent();
        asicContent.setSignedDocuments(getDocumentsToPreserve());
        return new ASiCEvidenceRecordManifestBuilder(
                asicContent, DigestAlgorithm.SHA256, "META-INF/evidencerecord.ers")
                .build();
    }

}
