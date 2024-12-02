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
package eu.europa.esig.dss.jades.requirements;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESSigningTimeType;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.TimeZone;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class JAdESBaselineBCompactSigTTest extends JAdESBaselineBCompactTest {

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        JAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setJadesSigningTimeType(JAdESSigningTimeType.SIG_T);
        signatureParameters.bLevel().setSigningDate(DSSUtils.getUtcDate(2024, Calendar.JANUARY, 1)); // before 2025-05-15
        return signatureParameters;
    }

    @Override
    protected void checkSigningTime(Map<String, Object> protectedHeaderMap) throws Exception {
        Number iat = (Number) protectedHeaderMap.get("iat");
        assertNull(iat);

        String sigT = (String) protectedHeaderMap.get("sigT");
        assertNotNull(sigT);

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'"); // RFC 3339
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        Date date = sdf.parse(sigT);
        assertNotNull(date);
    }

    @Override
    protected CertificateVerifier getCompleteCertificateVerifier() {
        CertificateVerifier certificateVerifier = super.getCompleteCertificateVerifier();
        certificateVerifier.setAlertOnNotYetValidCertificate(new SilentOnStatusAlert());
        return certificateVerifier;
    }

}
