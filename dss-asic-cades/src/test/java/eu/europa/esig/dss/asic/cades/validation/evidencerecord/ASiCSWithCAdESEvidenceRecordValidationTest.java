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
package eu.europa.esig.dss.asic.cades.validation.evidencerecord;

import eu.europa.esig.dss.asic.common.validation.AbstractASiCWithEvidenceRecordTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCSWithCAdESEvidenceRecordValidationTest extends AbstractASiCWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/er-one-file.asics");
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordDigestMatchers(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        List<XmlDigestMatcher> digestMatchers = evidenceRecords.get(0).getDigestMatchers();
        assertEquals(2, digestMatchers.size());

        boolean coveredFileFound = false;
        boolean notCoveredFileFound = false;
        for (XmlDigestMatcher digestMatcher : digestMatchers) {
            if (digestMatcher.isDataFound()) {
                assertEquals(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT, digestMatcher.getType());
                assertEquals("test.text", digestMatcher.getName());
                assertNotNull(digestMatcher.getDigestMethod());
                assertNotNull(digestMatcher.getDigestValue());
                assertTrue(digestMatcher.isDataIntact());
                coveredFileFound = true;
            } else {
                assertEquals(DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE, digestMatcher.getType());
                assertNull(digestMatcher.getName());
                assertNotNull(digestMatcher.getDigestMethod());
                assertNotNull(digestMatcher.getDigestValue());
                assertFalse(digestMatcher.isDataIntact());
                notCoveredFileFound = true;
            }
        }
        assertTrue(coveredFileFound);
        assertTrue(notCoveredFileFound);
    }

    @Override
    protected boolean allArchiveDataObjectsProvidedToValidation() {
        return false;
    }

}
