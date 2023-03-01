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
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CertificateTokenRefMatcherTest {

    private final CertificateTokenRefMatcher certificateTokenRefMatcher = new CertificateTokenRefMatcher();

    private static CertificateToken certificateToken;
    private static CertificateToken caCertificate;

    static {
        certificateToken = DSSUtils.loadCertificate(new File("src/test/resources/good-user.crt"));
        caCertificate = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.cer"));
    }

    @Test
    public void validCertRefTest() {
        CertificateRef validCertificateRef = new CertificateRef();
        validCertificateRef.setCertDigest(new Digest(DigestAlgorithm.SHA256, Utils.fromBase64("Mpwl3jOWWKPyZemwaU+5c/zYY2x1NBBaNU7Bo+BmmWU=")));
        validCertificateRef.setCertificateIdentifier(DSSASN1Utils.toSignerIdentifier(DSSASN1Utils.getIssuerSerial(certificateToken)));

        assertTrue(certificateTokenRefMatcher.match(certificateToken, validCertificateRef));
        assertTrue(certificateTokenRefMatcher.matchByDigest(certificateToken, validCertificateRef));
        assertTrue(certificateTokenRefMatcher.matchByIssuerName(certificateToken, validCertificateRef));
        assertTrue(certificateTokenRefMatcher.matchBySerialNumber(certificateToken, validCertificateRef));
        assertFalse(certificateTokenRefMatcher.matchByResponderId(certificateToken, validCertificateRef));
    }

    @Test
    public void invalidCertDigestTest() {
        CertificateRef validCertificateRef = new CertificateRef();
        validCertificateRef.setCertDigest(new Digest(DigestAlgorithm.SHA256, Utils.fromBase64("Zr4xWKz9SDQi7WF6ZcoC2hThEwXd4XW31xLF3Ey+9GE=")));
        validCertificateRef.setCertificateIdentifier(DSSASN1Utils.toSignerIdentifier(DSSASN1Utils.getIssuerSerial(certificateToken)));

        assertTrue(certificateTokenRefMatcher.match(certificateToken, validCertificateRef));
        assertFalse(certificateTokenRefMatcher.matchByDigest(certificateToken, validCertificateRef));
        assertTrue(certificateTokenRefMatcher.matchByIssuerName(certificateToken, validCertificateRef));
        assertTrue(certificateTokenRefMatcher.matchBySerialNumber(certificateToken, validCertificateRef));
        assertFalse(certificateTokenRefMatcher.matchByResponderId(certificateToken, validCertificateRef));
    }

    @Test
    public void invalidSerialIssuerTest() {
        CertificateRef validCertificateRef = new CertificateRef();
        validCertificateRef.setCertDigest(new Digest(DigestAlgorithm.SHA256, Utils.fromBase64("Mpwl3jOWWKPyZemwaU+5c/zYY2x1NBBaNU7Bo+BmmWU=")));
        validCertificateRef.setCertificateIdentifier(DSSASN1Utils.toSignerIdentifier(DSSASN1Utils.getIssuerSerial(caCertificate)));

        assertTrue(certificateTokenRefMatcher.match(certificateToken, validCertificateRef));
        assertTrue(certificateTokenRefMatcher.matchByDigest(certificateToken, validCertificateRef));
        assertFalse(certificateTokenRefMatcher.matchByIssuerName(certificateToken, validCertificateRef));
        assertFalse(certificateTokenRefMatcher.matchBySerialNumber(certificateToken, validCertificateRef));
        assertFalse(certificateTokenRefMatcher.matchByResponderId(certificateToken, validCertificateRef));
    }

    @Test
    public void invalidCertRefTest() {
        CertificateRef validCertificateRef = new CertificateRef();
        validCertificateRef.setCertDigest(new Digest(DigestAlgorithm.SHA256, Utils.fromBase64("Zr4xWKz9SDQi7WF6ZcoC2hThEwXd4XW31xLF3Ey+9GE=")));
        validCertificateRef.setCertificateIdentifier(DSSASN1Utils.toSignerIdentifier(DSSASN1Utils.getIssuerSerial(caCertificate)));

        assertFalse(certificateTokenRefMatcher.match(certificateToken, validCertificateRef));
        assertFalse(certificateTokenRefMatcher.matchByDigest(certificateToken, validCertificateRef));
        assertFalse(certificateTokenRefMatcher.matchByIssuerName(certificateToken, validCertificateRef));
        assertFalse(certificateTokenRefMatcher.matchBySerialNumber(certificateToken, validCertificateRef));
        assertFalse(certificateTokenRefMatcher.matchByResponderId(certificateToken, validCertificateRef));
    }

    @Test
    public void responderIdTest() {
        CertificateRef validCertificateRef = new CertificateRef();
        ResponderId responderId = new ResponderId(certificateToken.getSubject().getPrincipal(),
                CertificateExtensionsUtils.getSubjectKeyIdentifier(certificateToken).getSki());
        validCertificateRef.setResponderId(responderId);

        assertTrue(certificateTokenRefMatcher.match(certificateToken, validCertificateRef));
        assertFalse(certificateTokenRefMatcher.matchByDigest(certificateToken, validCertificateRef));
        assertFalse(certificateTokenRefMatcher.matchByIssuerName(certificateToken, validCertificateRef));
        assertFalse(certificateTokenRefMatcher.matchBySerialNumber(certificateToken, validCertificateRef));
        assertTrue(certificateTokenRefMatcher.matchByResponderId(certificateToken, validCertificateRef));
    }

    @Test
    public void invalidResponderIdTest() {
        CertificateRef validCertificateRef = new CertificateRef();
        ResponderId responderId = new ResponderId(caCertificate.getSubject().getPrincipal(),
                CertificateExtensionsUtils.getSubjectKeyIdentifier(caCertificate).getSki());
        validCertificateRef.setResponderId(responderId);

        assertFalse(certificateTokenRefMatcher.match(certificateToken, validCertificateRef));
        assertFalse(certificateTokenRefMatcher.matchByDigest(certificateToken, validCertificateRef));
        assertFalse(certificateTokenRefMatcher.matchByIssuerName(certificateToken, validCertificateRef));
        assertFalse(certificateTokenRefMatcher.matchBySerialNumber(certificateToken, validCertificateRef));
        assertFalse(certificateTokenRefMatcher.matchByResponderId(certificateToken, validCertificateRef));
    }

}
