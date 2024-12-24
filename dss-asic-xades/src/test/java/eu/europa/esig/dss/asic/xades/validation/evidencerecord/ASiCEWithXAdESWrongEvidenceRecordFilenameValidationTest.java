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
package eu.europa.esig.dss.asic.xades.validation.evidencerecord;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilterFactory;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordManifestBuilder;
import eu.europa.esig.dss.asic.common.extract.ASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.extract.DefaultASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.validation.AbstractASiCWithAsn1EvidenceRecordTestValidation;
import eu.europa.esig.dss.asic.xades.signature.DefaultASiCWithXAdESFilenameFactory;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ASiCEWithXAdESWrongEvidenceRecordFilenameValidationTest extends AbstractASiCWithAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        DSSDocument originalZip = new FileDocument("src/test/resources/validation/evidencerecord/er-multi-files.sce");

        ASiCContainerExtractor containerExtractor = DefaultASiCContainerExtractor.fromDocument(originalZip);
        ASiCContent asicContent = containerExtractor.extract();

        List<DSSDocument> evidenceRecordDocuments = asicContent.getEvidenceRecordDocuments();
        assertEquals(1, evidenceRecordDocuments.size());

        DSSDocument erDocument = evidenceRecordDocuments.get(0);

        DefaultASiCWithXAdESFilenameFactory filenameFactory = new DefaultASiCWithXAdESFilenameFactory();
        String erFilename = filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD);
        erDocument.setName(erFilename);

        ASiCEvidenceRecordManifestBuilder manifestBuilder = new ASiCEvidenceRecordManifestBuilder(asicContent,
                DigestAlgorithm.SHA256, erDocument.getName())
                .setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter())
                .setEvidenceRecordFilenameFactory(new DefaultASiCWithXAdESFilenameFactory());
        DSSDocument erManifest = manifestBuilder.build();

        asicContent.setEvidenceRecordManifestDocuments(Collections.singletonList(erManifest));

        return ZipUtils.getInstance().createZipArchive(asicContent);
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        // ignored because if invalid filename
        assertEquals(0, detachedEvidenceRecords.size());
    }
    
}
