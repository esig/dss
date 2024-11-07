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

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

// See DSS-2369
class CAdESLeveLTAExtensionExpiredSignatureTest extends AbstractCAdESTestExtension {

    private DSSDocument document;
    private CAdESService service;

    private CertificateVerifier certificateVerifier;

    @BeforeEach
    void init() {
        document = new FileDocument("src/test/resources/validation/Signature-C-CZ_SIX-1.p7m");

        certificateVerifier = getOfflineCertificateVerifier();
        certificateVerifier.setCheckRevocationForUntrustedChains(true);
        certificateVerifier.setAlertOnMissingRevocationData(new SilentOnStatusAlert());

        service = new CAdESService(certificateVerifier);
        service.setTspSource(getUsedTSPSourceAtExtensionTime());
    }

    @Test
    @Override
    public void extendAndVerify() throws Exception {
        Exception exception = assertThrows(AlertException.class, () -> extendSignature(document));
        assertTrue(exception.getMessage().contains("The signing certificate has expired and " +
                "there is no POE during its validity range :"));

        certificateVerifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());

        DSSDocument extendedDocument = extendSignature(document);
        verify(extendedDocument);
    }

    @Override
    protected CAdESService getSignatureServiceToExtend() {
        return service;
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(3, timestampList.size());

        int arcTstCounter = 0;
        for (TimestampWrapper timestampWrapper : timestampList) {
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            assertTrue(timestampWrapper.isSignatureIntact());
            assertTrue(timestampWrapper.isSignatureValid());
            if (timestampWrapper.getType().isArchivalTimestamp()) {
                ++arcTstCounter;
            }
        }
        assertEquals(2, arcTstCounter);
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        // certificate-values shall not be present
        assertEquals(SignatureLevel.CAdES_A, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures, DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_LTA;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_LTA;
    }

}
