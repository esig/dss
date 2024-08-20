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
package eu.europa.esig.dss.asic.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEWithCAdESFileRemovedTest extends AbstractASiCWithCAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/removed-doc.asice");
    }

    @Override
    protected void checkDigestMatchers(DiagnosticData diagnosticData) {
        super.checkDigestMatchers(diagnosticData);

        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        int signPropDMs = 0;
        int signDocValidDMs = 0;
        int signDocFailedDMs = 0;
        for (XmlDigestMatcher digestMatcher : signatureWrapper.getDigestMatchers()) {
            if (DigestMatcherType.MESSAGE_DIGEST.equals(digestMatcher.getType())) {
                assertTrue(digestMatcher.isDataFound());
                assertTrue(digestMatcher.isDataIntact());
                ++signPropDMs;
            } else if (DigestMatcherType.MANIFEST_ENTRY.equals(digestMatcher.getType())) {
                if (digestMatcher.isDataFound()) {
                    assertTrue(digestMatcher.isDataIntact());
                    ++signDocValidDMs;
                } else {
                    assertFalse(digestMatcher.isDataIntact());
                    ++signDocFailedDMs;
                }
            }
        }
        assertEquals(1, signPropDMs);
        assertEquals(2, signDocValidDMs);
        assertEquals(1, signDocFailedDMs);
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(3, timestampList.size());

        boolean cntTstFound = false;
        boolean sigTstFound = false;
        boolean arcTstFound = false;
        for (TimestampWrapper timestampWrapper : timestampList) {
            if (TimestampType.CONTENT_TIMESTAMP.equals(timestampWrapper.getType())) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertTrue(timestampWrapper.isMessageImprintDataIntact());
                cntTstFound = true;
            } else if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertTrue(timestampWrapper.isMessageImprintDataIntact());
                sigTstFound = true;
            } else if (TimestampType.CONTAINER_TIMESTAMP.equals(timestampWrapper.getType())) {
                assertEquals(ArchiveTimestampType.CAdES_DETACHED, timestampWrapper.getArchiveTimestampType());
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertTrue(timestampWrapper.isMessageImprintDataIntact());
                arcTstFound = true;
            }
        }
        assertTrue(cntTstFound);
        assertTrue(sigTstFound);
        assertTrue(arcTstFound);
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
    }

}
