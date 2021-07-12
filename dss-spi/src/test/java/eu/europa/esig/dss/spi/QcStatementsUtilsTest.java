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
package eu.europa.esig.dss.spi;

import eu.europa.esig.dss.enumerations.QCType;
import eu.europa.esig.dss.enumerations.SemanticsIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.PSD2QcType;
import eu.europa.esig.dss.model.x509.QCLimitValue;
import eu.europa.esig.dss.model.x509.QcStatements;
import eu.europa.esig.dss.model.x509.RoleOfPSP;
import org.bouncycastle.asn1.ASN1Sequence;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class QcStatementsUtilsTest {

    @Test
    void cert1() {
        CertificateToken cert = DSSUtils.loadCertificateFromBase64EncodedString(
                "MIII2TCCBsGgAwIBAgIJAqog3++ziaB0MA0GCSqGSIb3DQEBCwUAMHoxCzAJBgNVBAYTAkNaMSMwIQYDVQQDDBpJLkNBIFNTTCBFViBDQS9SU0EgMTAvMjAxNzEtMCsGA1UECgwkUHJ2bsOtIGNlcnRpZmlrYcSNbsOtIGF1dG9yaXRhLCBhLnMuMRcwFQYDVQRhDA5OVFJDWi0yNjQzOTM5NTAeFw0xOTEyMTcxNDA0MDNaFw0yMDEyMTYxNDA0MDNaMIIBBTEUMBIGA1UEAwwLY3JlZGl0YXMuY3oxETAPBgNVBAUTCDYzNDkyNTU1MRkwFwYDVQQHDBBQcmFoYSA4LCBLYXJsw61uMR0wGwYDVQQIDBRIbGF2bsOtIG3Em3N0byBQcmFoYTELMAkGA1UEBhMCQ1oxHDAaBgNVBAoME0JhbmthIENSRURJVEFTIGEucy4xFDASBgNVBAkMC1Nva29sb3Zza8OhMQ4wDAYDVQQRDAUxODYwMDEbMBkGA1UEYQwSUFNEQ1otQ05CLTYzNDkyNTU1MR0wGwYDVQQPDBRQcml2YXRlIE9yZ2FuaXphdGlvbjETMBEGCysGAQQBgjc8AgEDEwJDWjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOKZv4JkbWxjAaB/jkoQ/BS5WvItruLmQAF47D6AOZ1q6L958HmtjlXvmocttMh6f6iSOruwI9IFGOOtPvzFHOjZEcnE2L8pSyDRlV5eaLAi9JSVWYar48QrOkJWwbnX8W6LclBppU4ELPsrFS+wR2KabKOF0FffelUTtzUF9PPATElvMQlXaf0Mfa4uAYWdH4rWfNvIW6u6BO6v/I+6Bx59yyx64TUe57bSTNlRDjBR0bc2Ssb0s17j7tscGI/80zoSrHdUqjLWvNdS7FFUHA+VMum+L1rNjzNYAXvVyBWcoYNZ/kEd8pDMWHHWEuxl9XAQzYFwZxcclfJsYByt618CAwEAAaOCA9MwggPPMBYGA1UdEQQPMA2CC2NyZWRpdGFzLmN6MAkGA1UdEwQCMAAwggE5BgNVHSAEggEwMIIBLDCCAR0GDSsGAQQBgbhICgEoAQEwggEKMB0GCCsGAQUFBwIBFhFodHRwOi8vd3d3LmljYS5jejCB6AYIKwYBBQUHAgIwgdsagdhUZW50byBrdmFsaWZpa292YW55IGNlcnRpZmlrYXQgcHJvIGF1dGVudGl6YWNpIGludGVybmV0b3Z5Y2ggc3RyYW5layBieWwgdnlkYW4gdiBzb3VsYWR1IHMgbmFyaXplbmltIEVVIGMuIDkxMC8yMDE0LlRoaXMgaXMgYSBxdWFsaWZpZWQgY2VydGlmaWNhdGUgZm9yIHdlYnNpdGUgYXV0aGVudGljYXRpb24gYWNjb3JkaW5nIHRvIFJlZ3VsYXRpb24gKEVVKSBObyA5MTAvMjAxNC4wCQYHBACL7EABBDCBjAYDVR0fBIGEMIGBMCmgJ6AlhiNodHRwOi8vcWNybGRwMS5pY2EuY3ovcWN3MTdfcnNhLmNybDApoCegJYYjaHR0cDovL3FjcmxkcDIuaWNhLmN6L3FjdzE3X3JzYS5jcmwwKaAnoCWGI2h0dHA6Ly9xY3JsZHAzLmljYS5jei9xY3cxN19yc2EuY3JsMGMGCCsGAQUFBwEBBFcwVTApBggrBgEFBQcwAoYdaHR0cDovL3EuaWNhLmN6L3FjdzE3X3JzYS5jZXIwKAYIKwYBBQUHMAGGHGh0dHA6Ly9vY3NwLmljYS5jei9xY3cxN19yc2EwDgYDVR0PAQH/BAQDAgWgMIH/BggrBgEFBQcBAwSB8jCB7zAIBgYEAI5GAQEwEwYGBACORgEGMAkGBwQAjkYBBgMwVwYGBACORgEFME0wLRYnaHR0cHM6Ly93d3cuaWNhLmN6L1pwcmF2eS1wcm8tdXppdmF0ZWxlEwJjczAcFhZodHRwczovL3d3dy5pY2EuY3ovUERTEwJlbjB1BgYEAIGYJwIwazBMMBEGBwQAgZgnAQEMBlBTUF9BUzARBgcEAIGYJwECDAZQU1BfUEkwEQYHBACBmCcBAwwGUFNQX0FJMBEGBwQAgZgnAQQMBlBTUF9JQwwTQ3plY2ggTmF0aW9uYWwgQmFuawwGQ1otQ05CMB8GA1UdIwQYMBaAFD2vGQiXehCMvCjBRm2XSFpI/ALKMB0GA1UdDgQWBBTgz4IhX8EjbmNoyVpi4k8TRVEdRDAnBgNVHSUEIDAeBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4ICAQBqfekq6C3hscyWRnKIhSvGQRVaWH8h0qV0UnVAUt3z0FX/EiMSteL+yHmFMaSz68vkEO0nGIxEp193uF1ZFg4n/hYg5RWUNABDdIpX1nST5ZYCqtXqNDPc8EqeJjVrFqo06+NpscmCRep7q3T9dIMC7ObZN2aVJ1N6Rt3EcotWqPa0t0V7soa8cM+raSv4VQWs4FUw2kg1rd6lpLWDU2H19jw3+C3zRSpO7CiLeELrly0H9asOhfxZYSdLhqpP/onuvvxyu9V/auJ6+YW7FUBk95mc8KrJ96XBlqcAp3/mq14JPRHpjVunDaiQUsLVBayLZ0S5bJe4wrvzXQ9aTj14kRbT6/xKeYA46zanJ4LjDJ5n8pzJyh0l+zFqs+5ZygKCxjl0GBXS4L79JVsCjZgm5R4i9qmxgsojOoYwTk2LE7ED606ei8DnlND9F/uRLrlrBodXwh/eHtHpHPcQxvhHtbeYsZTH/NC4MCG7t9USdLycoQYk3JD5Qk+yo+pDatpJpgnK4M8F7ANNT9c7Xmt6Kwmidulb8LcTvMPU19BqgjX6jewBiUh+ZF9d2W+W/zIz4smpSTT/8tRAFi11RT0wcM8wYCvavSiAxrbuslMjHW6M5T++GAd4zgw1VM56vsDb5tYNmNt311tk62YoKn6P5FBCi7uIbg7zv0o+RdLXhg==");
        assertNotNull(cert);

        QcStatements qcStatements = QcStatementUtils.getQcStatements(cert);
        assertNotNull(qcStatements);
        assertTrue(qcStatements.isQcCompliance());
        assertFalse(qcStatements.isQcQSCD());
        assertNull(qcStatements.getQcSemanticsIdentifier());
        assertNull(qcStatements.getQcLimitValue());
        assertNull(qcStatements.getQcEuRetentionPeriod());
        assertEquals(2, qcStatements.getQcEuPDS().size());
        assertEquals(1, qcStatements.getQcTypes().size());
        assertTrue(qcStatements.getQcTypes().contains(QCType.QCT_WEB));
        PSD2QcType psd2QcType = qcStatements.getPsd2QcType();
        assertNotNull(psd2QcType);
        assertNotNull(psd2QcType.getNcaId());
        assertNotNull(psd2QcType.getNcaName());
        assertEquals(4, psd2QcType.getRolesOfPSP().size());
    }

    @Test
    void cert2() {
        CertificateToken caTokenA = DSSUtils.loadCertificateFromBase64EncodedString(
                "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");

        QcStatements qcStatements = QcStatementUtils.getQcStatements(caTokenA);
        assertNotNull(qcStatements);
        assertTrue(qcStatements.isQcCompliance());
        assertTrue(qcStatements.isQcQSCD());
        assertNull(qcStatements.getQcLimitValue());
        assertNull(qcStatements.getPsd2QcType());
        assertNull(qcStatements.getQcEuRetentionPeriod());
        assertEquals(1, qcStatements.getQcEuPDS().size());
        assertEquals(1, qcStatements.getQcTypes().size());
        assertTrue(qcStatements.getQcTypes().contains(QCType.QCT_ESEAL));

        assertNotNull(qcStatements.getQcSemanticsIdentifier());
        assertEquals(SemanticsIdentifier.qcsSemanticsIdLegal, qcStatements.getQcSemanticsIdentifier());
    }

    @Test
    void certWithLegislation() {
        CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/john_doe_tc.crt"));

        QcStatements qcStatements = QcStatementUtils.getQcStatements(certificate);
        assertNotNull(qcStatements);
        List<String> qcLegislationCountryCodes = qcStatements.getQcLegislationCountryCodes();
        assertNotNull(qcLegislationCountryCodes);
        assertEquals(1, qcLegislationCountryCodes.size());
        assertTrue(qcLegislationCountryCodes.contains("TC"));
    }

    @Test
    void certWithQCLimitValue() {
        CertificateToken certificateToken = DSSUtils.loadCertificateFromBase64EncodedString("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");
        QcStatements qcStatements = QcStatementUtils.getQcStatements(certificateToken);
        assertNotNull(qcStatements);
        QCLimitValue qcLimitValue = qcStatements.getQcLimitValue();
        assertNotNull(qcLimitValue);
        assertEquals("EUR", qcLimitValue.getCurrency());
        assertEquals(0, qcLimitValue.getAmount());
        assertEquals(0, qcLimitValue.getExponent());
    }

    @Test
    void certWithPSD2QcStatement() {
        CertificateToken cert = DSSUtils.loadCertificateFromBase64EncodedString(
                "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");
        assertNotNull(cert);

        QcStatements qcStatements = QcStatementUtils.getQcStatements(cert);
        assertNotNull(qcStatements);

        PSD2QcType psd2QcType = qcStatements.getPsd2QcType();
        assertNotNull(psd2QcType);
        List<RoleOfPSP> rolesOfPSP = psd2QcType.getRolesOfPSP();
        assertNotNull(rolesOfPSP);
        for (RoleOfPSP roleOfPSP : rolesOfPSP) {
            assertNotNull(roleOfPSP);
            assertNotNull(roleOfPSP.getPspOid());
            assertNotNull(roleOfPSP.getPspName());
        }
        assertNotNull(psd2QcType.getNcaName());
        assertNotNull(psd2QcType.getNcaId());
    }

    @Test
    void certWithoutQCStatements() {
        CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/TSP_Certificate_2014.crt"));
        QcStatements qcStatements = QcStatementUtils.getQcStatements(certificate);
        assertNull(qcStatements);
    }

    @Test
    void qcStatementNullSequence() {
        assertNull(QcStatementUtils.getQcStatements((ASN1Sequence) null));
    }

}
