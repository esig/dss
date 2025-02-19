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
package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.pki.x509.revocation.crl.PKICRLSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import org.junit.jupiter.api.Test;

import java.util.Calendar;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESExtensionTToLTNotFreshRevocationTest extends XAdESExtensionTToLTTest {

    @Override
    protected TSPSource getUsedTSPSourceAtSignatureTime() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND, -1);
        return getKeyStoreTSPSourceByNameAndTime(GOOD_TSA, calendar.getTime());
    }

    @Override
    protected PKICRLSource pkiCRLSource() {
        PKICRLSource crlSource = super.pkiCRLSource();

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MINUTE, -30);
        crlSource.setThisUpdate(calendar.getTime());

        calendar.add(Calendar.MINUTE, 60);
        crlSource.setNextUpdate(calendar.getTime());

        return crlSource;
    }

    @Override
    protected CertificateVerifier getCompleteCertificateVerifier() {
        CertificateVerifier certificateVerifier = super.getCompleteCertificateVerifier();
        certificateVerifier.setCrlSource(pkiCRLSource());
        certificateVerifier.setOcspSource(pkiDelegatedOCSPSource());
        certificateVerifier.setRevocationFallback(true);
        certificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new ExceptionOnStatusAlert());
        return certificateVerifier;
    }

    @Test
    @Override
    public void extendAndVerify() throws Exception {
        Exception exception = assertThrows(AlertException.class, super::extendAndVerify);
        assertTrue(exception.getMessage().contains("Fresh revocation data is missing for one or more certificate(s)."));
        assertTrue(exception.getMessage().contains("No revocation data found after the best signature time"));
        assertTrue(exception.getMessage().contains("The nextUpdate available after :"));
    }

}
