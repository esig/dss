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

import eu.europa.esig.dss.asic.common.validation.AbstractASiCWithAsn1EvidenceRecordTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEWithCAdESAsn1EvidenceRecordNoHashTreeFullRenewalValidationTest extends AbstractASiCWithAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/er-asn1-no-hashtree-full-renewal.sce");
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordTimestamps(diagnosticData);

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(3, timestampList.size());

        boolean arcTstFound = false;
        boolean tstRenewalFound = false;
        boolean hashTreeRenewalTstFound = false;
        for (TimestampWrapper timestampWrapper : timestampList) {
            if (EvidenceRecordTimestampType.ARCHIVE_TIMESTAMP == timestampWrapper.getEvidenceRecordTimestampType()) {
                List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
                assertEquals(1, digestMatchers.size());
                assertEquals(DigestMatcherType.MESSAGE_IMPRINT, digestMatchers.get(0).getType());
                assertTrue(digestMatchers.get(0).isDataFound());
                assertTrue(digestMatchers.get(0).isDataIntact());
                arcTstFound = true;

            } else if (EvidenceRecordTimestampType.TIMESTAMP_RENEWAL_ARCHIVE_TIMESTAMP == timestampWrapper.getEvidenceRecordTimestampType()) {
                boolean messageImprintFound = false;
                boolean arcTstRefFound = false;
                for (XmlDigestMatcher xmlDigestMatcher : timestampWrapper.getDigestMatchers()) {
                    assertTrue(xmlDigestMatcher.isDataFound());
                    assertTrue(xmlDigestMatcher.isDataIntact());
                    if (DigestMatcherType.MESSAGE_IMPRINT == xmlDigestMatcher.getType()) {
                        messageImprintFound = true;
                    } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP == xmlDigestMatcher.getType()) {
                        arcTstRefFound = true;
                    }
                }
                assertTrue(messageImprintFound);
                assertTrue(arcTstRefFound);
                // only one digest in reduced hashtree -> same as message-imprint
                assertEquals(timestampWrapper.getDigestMatchers().get(0).getDigestMethod(), timestampWrapper.getDigestMatchers().get(1).getDigestMethod());
                assertArrayEquals(timestampWrapper.getDigestMatchers().get(0).getDigestValue(), timestampWrapper.getDigestMatchers().get(1).getDigestValue());
                tstRenewalFound = true;

            } else if (EvidenceRecordTimestampType.HASH_TREE_RENEWAL_ARCHIVE_TIMESTAMP == timestampWrapper.getEvidenceRecordTimestampType()) {
                boolean messageImprintFound = false;
                boolean arcDataObjRefFound = false;
                for (XmlDigestMatcher xmlDigestMatcher : timestampWrapper.getDigestMatchers()) {
                    assertTrue(xmlDigestMatcher.isDataFound());
                    assertTrue(xmlDigestMatcher.isDataIntact());
                    if (DigestMatcherType.MESSAGE_IMPRINT == xmlDigestMatcher.getType()) {
                        messageImprintFound = true;
                    } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == xmlDigestMatcher.getType()) {
                        arcDataObjRefFound = true;
                    }
                }
                assertTrue(messageImprintFound);
                assertTrue(arcDataObjRefFound);
                // only one digest in reduced hashtree -> same as message-imprint
                assertEquals(timestampWrapper.getDigestMatchers().get(0).getDigestMethod(), timestampWrapper.getDigestMatchers().get(1).getDigestMethod());
                assertArrayEquals(timestampWrapper.getDigestMatchers().get(0).getDigestValue(), timestampWrapper.getDigestMatchers().get(1).getDigestValue());
                hashTreeRenewalTstFound = true;
            }
        }
        assertTrue(arcTstFound);
        assertTrue(tstRenewalFound);
        assertTrue(hashTreeRenewalTstFound);
    }

}
