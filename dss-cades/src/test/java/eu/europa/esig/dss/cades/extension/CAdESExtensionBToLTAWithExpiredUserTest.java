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

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import org.junit.jupiter.api.BeforeEach;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESExtensionBToLTAWithExpiredUserTest extends AbstractCAdESTestExtension {

    private CAdESService service;

    @BeforeEach
    void init() throws Exception {
        service = new CAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
    }

    @Override
    protected CertificateVerifier getCompleteCertificateVerifier() {
        CertificateVerifier certificateVerifier = super.getCompleteCertificateVerifier();
        certificateVerifier.setRevocationFallback(true);
        certificateVerifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());
        return certificateVerifier;
    }

    @Override
    protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
        CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
        certificateVerifier.setAlertOnExpiredCertificate(new ExceptionOnStatusAlert());

        CAdESService service = new CAdESService(certificateVerifier);
        service.setTspSource(getUsedTSPSourceAtExtensionTime());

        Exception exception = assertThrows(AlertException.class, () -> service.extendDocument(signedDocument, getExtensionParameters()));
        assertTrue(exception.getMessage().contains("Error on signature augmentation"));
        assertTrue(exception.getMessage().contains("is expired at signing time"));

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(getSigningCert().getNotAfter());
        calendar.add(Calendar.MONTH, -6);
        Date tstTime = calendar.getTime();

        service.setTspSource(getGoodTsaByTime(tstTime));

        exception = assertThrows(AlertException.class, () -> service.extendDocument(signedDocument, getExtensionParameters()));
        assertTrue(exception.getMessage().contains("Error on signature augmentation"));
        assertTrue(exception.getMessage().contains("is expired at signing time"));

        certificateVerifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());

        DSSDocument extendedDocument = service.extendDocument(signedDocument, getExtensionParameters());
        assertNotNull(extendedDocument);

        certificateVerifier.setAlertOnExpiredCertificate(new ExceptionOnStatusAlert());

        service.setTspSource(getGoodTsa());

        extendedDocument = service.extendDocument(extendedDocument, getExtensionParameters());
        assertNotNull(extendedDocument);
        return extendedDocument;
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        if (SignatureLevel.CAdES_BASELINE_LTA.equals(signature.getSignatureFormat())) {
            List<TimestampWrapper> timestampList = signature.getTimestampList();
            assertEquals(3, timestampList.size());
            int signatureTstCounter = 0;
            int archiveTstCounter = 0;
            for (TimestampWrapper timestampWrapper : timestampList) {
                if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
                    ++signatureTstCounter;
                } else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
                    ++archiveTstCounter;
                }
            }
            assertEquals(1, signatureTstCounter);
            assertEquals(2, archiveTstCounter);
        }
    }

    @Override
    protected CAdESService getSignatureServiceToExtend() {
        return service;
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_B;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.CAdES_BASELINE_LTA;
    }

    @Override
    protected String getSigningAlias() {
        return EXPIRED_USER;
    }

}
