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
package eu.europa.esig.dss.cades.extension;

import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.FoundRevocationsProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampHashIndexVersion;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.event.Level;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESExtensionCNoTstToLTATest extends AbstractCAdESTestExtension {

    private DSSDocument document;
    private CAdESService service;

    @BeforeEach
    void init() {
        document = new FileDocument("src/test/resources/validation/cades-e-lt.p7m");

        CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
        certificateVerifier.setCheckRevocationForUntrustedChains(true);
        certificateVerifier.setAlertOnMissingRevocationData(new LogOnStatusAlert(Level.WARN));
        certificateVerifier.setAlertOnExpiredCertificate(new LogOnStatusAlert(Level.WARN));

        service = new CAdESService(certificateVerifier);
        service.setTspSource(getUsedTSPSourceAtExtensionTime());
    }

    @Override
    protected DSSDocument getSignedDocument(DSSDocument doc) {
        return document;
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkFinalLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.CAdES_A, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkCertificateValuesEncapsulation(DiagnosticData diagnosticData) {
        super.checkCertificateValuesEncapsulation(diagnosticData);

        List<TimestampWrapper> timestamps = diagnosticData.getTimestampList();

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        FoundCertificatesProxy foundCertificates = signature.foundCertificates();
        assertEquals(timestamps.size() == 1 ? 1 : 2, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.SIGNED_DATA).size()); // +1 added
        assertEquals(3, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
    }

    @Override
    protected void checkRevocationDataEncapsulation(DiagnosticData diagnosticData) {
        super.checkRevocationDataEncapsulation(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        FoundRevocationsProxy foundRevocations = signature.foundRevocations();
        assertEquals(0, foundRevocations.getRelatedRevocationsByOrigin(RevocationOrigin.CMS_SIGNED_DATA).size()); // not added, avoid duplication
        assertEquals(3, foundRevocations.getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES).size());
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        List<TimestampWrapper> timestamps = diagnosticData.getTimestampList();
        assertTrue(Utils.isCollectionNotEmpty(timestamps));
        int signatureTimestampCounter = 0;
        int archiveTimestampV2Counter = 0;
        int archiveTimestampV3Counter = 0;
        for (TimestampWrapper timestamp : timestamps) {
            if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
                if (ArchiveTimestampType.CAdES_V2 == timestamp.getArchiveTimestampType()) {
                    ++archiveTimestampV2Counter;

                } else if (ArchiveTimestampType.CAdES_V3 == timestamp.getArchiveTimestampType()) {
                    assertEquals(ArchiveTimestampHashIndexVersion.ATS_HASH_INDEX_V3, timestamp.getAtsHashIndexVersion());
                    assertTrue(timestamp.isAtsHashIndexValid());
                    assertTrue(Utils.isCollectionEmpty(timestamp.getAtsHashIndexValidationMessages()));

                    assertEquals(1, timestamp.getTimestampedSignedData().size());
                    assertEquals(1, timestamp.getTimestampedSignatures().size());
                    assertEquals(1, timestamp.getTimestampedTimestamps().size());
                    assertEquals(5, timestamp.getTimestampedCertificates().size());
                    assertEquals(3, timestamp.getTimestampedRevocations().size());

                    ++archiveTimestampV3Counter;
                }

            } else if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestamp.getType())) {
                assertNull(timestamp.getAtsHashIndexVersion());
                signatureTimestampCounter++;
            }
        }
        assertEquals(1, signatureTimestampCounter);
        assertEquals(0, archiveTimestampV2Counter);
        assertEquals(timestamps.size() == 1 ? 0 : 1, archiveTimestampV3Counter);
    }

    @Override
    protected CAdESService getSignatureServiceToExtend() {
        return service;
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.CAdES_C;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_LTA;
    }

}
