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
package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.BeforeEach;

import java.util.Calendar;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESExtensionTToLTAWithInvalidMessageImprintTstTest extends AbstractXAdESTestExtension {

    private CertificateVerifier certificateVerifier;
    private XAdESService service;

    @BeforeEach
    public void init() throws Exception {
        certificateVerifier = getCompleteCertificateVerifier();
        certificateVerifier.setAlertOnInvalidTimestamp(new SilentOnStatusAlert());

        service = new XAdESService(certificateVerifier);
        service.setTspSource(getGoodTsa());
    }

    @Override
    protected CertificateVerifier getCompleteCertificateVerifier() {
        CertificateVerifier certificateVerifier = super.getCompleteCertificateVerifier();
        certificateVerifier.setRevocationFallback(true);
        return certificateVerifier;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        XAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setSignWithExpiredCertificate(true);
        return signatureParameters;
    }

    @Override
    protected TSPSource getUsedTSPSourceAtSignatureTime() {
        return new MockInvalidTspSource();
    }

    @Override
    protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
        certificateVerifier.setAlertOnExpiredSignature(new ExceptionOnStatusAlert());

        Exception exception = assertThrows(AlertException.class, () -> super.extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains(
                "The signing certificate has expired and there is no POE during its validity range"));

        certificateVerifier.setAlertOnExpiredSignature(new SilentOnStatusAlert());

        return super.extendSignature(signedDocument);
    }

    @Override
    protected void checkOriginalLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XAdES_BASELINE_T, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
        assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
        assertFalse(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
        assertFalse(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkFinalLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XAdES_BASELINE_LTA, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
        assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
        assertFalse(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
        assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkTLevelAndValid(DiagnosticData diagnosticData) {
        assertTrue(diagnosticData.isThereTLevel(diagnosticData.getFirstSignatureId()));
        assertFalse(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        // skip (invalid timestamp)
    }

    @Override
    protected XAdESService getSignatureServiceToExtend() {
        return service;
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_T;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_LTA;
    }

    @Override
    protected String getSigningAlias() {
        return EXPIRED_USER;
    }

    @SuppressWarnings("serial")
    private class MockInvalidTspSource implements TSPSource {

        @Override
        public TimestampBinary getTimeStampResponse(DigestAlgorithm digestAlgorithm, byte[] digest) throws DSSException {
            digest = DSSUtils.digest(digestAlgorithm, "Hello World".getBytes());
            return getTspSource().getTimeStampResponse(digestAlgorithm, digest);
        }

        private TSPSource getTspSource() {
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(new Date());
            calendar.add(Calendar.MONTH, -6);
            Date tstTime = calendar.getTime();
            return getGoodTsaByTime(tstTime);
        }

    }

}
