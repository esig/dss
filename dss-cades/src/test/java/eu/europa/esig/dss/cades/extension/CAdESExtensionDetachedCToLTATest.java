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
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
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
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.event.Level;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("atst-v2")
class CAdESExtensionDetachedCToLTATest extends AbstractCAdESTestExtension {

    private DSSDocument document;
    private DSSDocument detachedDocument;
    private CAdESService service;

    @BeforeEach
    void init() {
        document = new InMemoryDocument(CAdESExtensionDetachedCToLTATest.class.getResourceAsStream("/validation/dss-1469/cadesLTAwithATv2.sig"));
        detachedDocument = new InMemoryDocument(CAdESExtensionDetachedCToLTATest.class.getResourceAsStream("/validation/dss-1469/screenshot2.png"));

        CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
        certificateVerifier.setCheckRevocationForUntrustedChains(true);
        certificateVerifier.setAlertOnMissingRevocationData(new LogOnStatusAlert(Level.WARN));
        certificateVerifier.setAlertOnInvalidTimestamp(new LogOnStatusAlert(Level.WARN));
        certificateVerifier.setAlertOnExpiredCertificate(new LogOnStatusAlert(Level.WARN));

        service = new CAdESService(certificateVerifier);
        service.setTspSource(getUsedTSPSourceAtExtensionTime());
    }

    @Override
    protected String getOriginalDocumentPath() {
        return "/validation/dss-1469/screenshot2.png";
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(detachedDocument);
    }

    @Override
    protected DSSDocument getSignedDocument(DSSDocument doc) {
        return document;
    }

    @Override
    protected CAdESSignatureParameters getSignatureParameters() {
        CAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        return signatureParameters;
    }

    @Override
    protected CAdESSignatureParameters getExtensionParameters() {
        CAdESSignatureParameters extensionParameters = super.getExtensionParameters();
        extensionParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        extensionParameters.setDetachedContents(getDetachedContents());
        return extensionParameters;
    }

    @Override
    protected void checkFileExtension(DSSDocument document) {
        // skip
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        // skip
    }

    @Test
    @Override
    public void extendAndVerify() throws Exception {
        DSSDocument extendedDocument = extendSignature(document);
        verify(extendedDocument);
    }

    @Override
    protected void checkFinalLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.CAdES_C, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkCertificateValuesEncapsulation(DiagnosticData diagnosticData) {
        super.checkCertificateValuesEncapsulation(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        FoundCertificatesProxy foundCertificates = signature.foundCertificates();
        // not changed because of CAdES_v2
        assertEquals(4, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.SIGNED_DATA).size());
        assertEquals(2, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
    }

    @Override
    protected void checkRevocationDataEncapsulation(DiagnosticData diagnosticData) {
        super.checkRevocationDataEncapsulation(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        FoundRevocationsProxy foundRevocations = signature.foundRevocations();
        assertEquals(0, foundRevocations.getRelatedRevocationsByOrigin(RevocationOrigin.CMS_SIGNED_DATA).size());
        assertEquals(2, foundRevocations.getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES).size());
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
                    assertNull(timestamp.getAtsHashIndexVersion());
                    ++archiveTimestampV2Counter;

                } else if (ArchiveTimestampType.CAdES_V3 == timestamp.getArchiveTimestampType()) {
                    assertEquals(ArchiveTimestampHashIndexVersion.ATS_HASH_INDEX_V3, timestamp.getAtsHashIndexVersion());
                    assertTrue(timestamp.isAtsHashIndexValid());
                    assertTrue(Utils.isCollectionEmpty(timestamp.getAtsHashIndexValidationMessages()));

                    assertEquals(1, timestamp.getTimestampedSignedData().size());
                    assertEquals(1, timestamp.getTimestampedSignatures().size());
                    assertEquals(2, timestamp.getTimestampedTimestamps().size());
                    assertEquals(6, timestamp.getTimestampedCertificates().size());
                    assertEquals(2, timestamp.getTimestampedRevocations().size());

                    ++archiveTimestampV3Counter;
                }

            } else if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestamp.getType())) {
                assertNull(timestamp.getAtsHashIndexVersion());
                signatureTimestampCounter++;
            }
        }
        assertEquals(1, signatureTimestampCounter);
        assertEquals(1, archiveTimestampV2Counter);
        assertEquals(timestamps.size() == 2 ? 0 : 1, archiveTimestampV3Counter);
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
