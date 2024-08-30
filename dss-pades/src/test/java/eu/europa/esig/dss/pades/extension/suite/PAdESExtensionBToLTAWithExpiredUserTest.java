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
package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import org.junit.jupiter.api.BeforeEach;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESExtensionBToLTAWithExpiredUserTest extends AbstractPAdESTestExtension {

    private PAdESService service;

    @BeforeEach
    void init() throws Exception {
        service = new PAdESService(getCompleteCertificateVerifier());
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
    protected DSSDocument extendSignature(DSSDocument signedDocument) {
        CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
        certificateVerifier.setAlertOnExpiredCertificate(new ExceptionOnStatusAlert());

        PAdESService service = new PAdESService(certificateVerifier);
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
        if (SignatureLevel.PAdES_BASELINE_LTA.equals(signature.getSignatureFormat())) {
            List<TimestampWrapper> timestampList = signature.getTimestampList();
            assertEquals(3, timestampList.size());
            int signatureTstCounter = 0;
            int archiveTstCounter = 0;
            for (TimestampWrapper timestampWrapper : timestampList) {
                if (TimestampType.DOCUMENT_TIMESTAMP.equals(timestampWrapper.getType())) {
                    if (Utils.isCollectionEmpty(timestampWrapper.getTimestampedRevocations())) {
                        ++signatureTstCounter;
                    } else {
                        ++archiveTstCounter;
                    }
                }
            }
            assertEquals(1, signatureTstCounter);
            assertEquals(2, archiveTstCounter);
        }
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        super.checkSignatureLevel(diagnosticData);
    }

    @Override
    protected PAdESService getSignatureServiceToExtend() {
        return service;
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.PAdES_BASELINE_B;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.PAdES_BASELINE_LTA;
    }

    @Override
    protected String getSigningAlias() {
        return EXPIRED_USER;
    }

}
