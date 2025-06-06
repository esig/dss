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
package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampHashIndexVersion;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESLevelLTAHashIndexRevValuesOCSPDigestTest extends AbstractCAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(CAdESLevelLTAHashIndexRevValuesOCSPDigestTest.class.getResourceAsStream("/validation/cades-ats-v3-rev-val-ocsp.p7s"));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.CAdES_C, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        assertEquals(3, diagnosticData.getTimestampList().size());

        boolean sigTstFound = false;
        boolean arcTstV2Found = false;
        boolean arcTstV3Found = false;
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            if (TimestampType.SIGNATURE_TIMESTAMP == timestampWrapper.getType()) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertTrue(timestampWrapper.isMessageImprintDataIntact());
                assertTrue(timestampWrapper.isSignatureIntact());
                assertTrue(timestampWrapper.isSignatureValid());

                assertNull(timestampWrapper.getAtsHashIndexVersion());

                sigTstFound = true;

            } else if (TimestampType.ARCHIVE_TIMESTAMP == timestampWrapper.getType()) {
                if (ArchiveTimestampType.CAdES_V2 == timestampWrapper.getArchiveTimestampType()) {
                    assertTrue(timestampWrapper.isMessageImprintDataFound());
                    assertTrue(timestampWrapper.isMessageImprintDataIntact());
                    assertTrue(timestampWrapper.isSignatureIntact());
                    assertTrue(timestampWrapper.isSignatureValid());

                    assertNull(timestampWrapper.getAtsHashIndexVersion());
                    arcTstV2Found = true;

                } else if (ArchiveTimestampType.CAdES_V3 == timestampWrapper.getArchiveTimestampType()) {
                    assertTrue(timestampWrapper.isMessageImprintDataFound());
                    assertTrue(timestampWrapper.isMessageImprintDataIntact());
                    assertTrue(timestampWrapper.isSignatureIntact());
                    assertTrue(timestampWrapper.isSignatureValid());

                    assertEquals(ArchiveTimestampHashIndexVersion.ATS_HASH_INDEX_V3, timestampWrapper.getAtsHashIndexVersion());
                    assertFalse(timestampWrapper.isAtsHashIndexValid());
                    assertFalse(Utils.isCollectionEmpty(timestampWrapper.getAtsHashIndexValidationMessages()));
                    assertTrue(timestampWrapper.getAtsHashIndexValidationMessages().contains(
                            "ats-hash-index attribute contains crls present outside of SignedData.crls."));

                    arcTstV3Found = true;
                }
            }
        }
        assertTrue(sigTstFound);
        assertTrue(arcTstV2Found);
        assertTrue(arcTstV3Found);
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertTrue(signature.isSigningCertificateIdentified());
        assertTrue(signature.isSigningCertificateReferencePresent());
        assertFalse(signature.isSigningCertificateReferenceUnique());
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanCertificateObjects()));
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanCertificateReferences()));
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanRevocationObjects()));
        assertFalse(Utils.isCollectionEmpty(diagnosticData.getAllOrphanRevocationReferences()));
    }

}