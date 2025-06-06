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
package eu.europa.esig.dss.asic.cades.preservation.container;

import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ASiCSWithCAdESAddContainerXMLEvidenceRecordMultipleFilesTest extends AbstractASiCWithCAdESTestAddContainerEvidenceRecord {

    private static List<DSSDocument> originalDocuments;

    private List<DSSDocument> documentsToPreserve;

    @BeforeAll
    public static void init() {
        originalDocuments = Arrays.asList(
                new FileDocument("src/test/resources/signable/empty.zip"),
                new FileDocument("src/test/resources/signable/test.txt"),
                new FileDocument("src/test/resources/signable/test.zip")
        );
    }

    @Override
    protected List<DSSDocument> getDocumentsToPreserve() {
        return documentsToPreserve;
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/incorporation/evidence-record-package-zip.xml");
    }

    @Override
    protected ASiCContainerType getASiCContainerType() {
        return ASiCContainerType.ASiC_S;
    }

    @Override
    protected EvidenceRecordTypeEnum getEvidenceRecordType() {
        return EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD;
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 1;
    }

    @Test
    @Override
    public void addERAndValidate() {
        documentsToPreserve = originalDocuments;

        Exception exception = assertThrows(IllegalArgumentException.class, super::addERAndValidate);
        assertEquals("Only one original document is expected for the ASiC-S container type! " +
                "If required, please create a 'package.zip' and provide it directly as a parameter. " +
                "Otherwise, please switch to the ASiC-E type.", exception.getMessage());

        Calendar calendar = Calendar.getInstance();
        calendar.clear();
        calendar.set(2025, Calendar.JANUARY, 1);

        DSSDocument packageZip = ZipUtils.getInstance().createZipArchive(originalDocuments, calendar.getTime(), null);
        packageZip.setName("package.zip");
        documentsToPreserve = Collections.singletonList(packageZip);

        super.addERAndValidate();
    }

}