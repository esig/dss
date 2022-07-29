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
package eu.europa.esig.dss.tsl.dto.condition;

import eu.europa.esig.dss.enumerations.QCTypeEnum;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class QcStatementConditionTest {

    private static CertificateToken uaESignCertificate;
    private static CertificateToken eSealCertificate;
    private static CertificateToken otherOidCertificate;

    @BeforeAll
    public static void init() {
        uaESignCertificate = DSSUtils.loadCertificateFromBase64EncodedString("MIIE/jCCBKSgAwIBAgIUNHSLOUor3i8EAAAAzfVDAFlVhwAwCgYIKoZIzj0EAwIwgdgxIDAeBgNVBAoMF1N0YXRlIGVudGVycHJpc2UgIkRJSUEiMTAwLgYDVQQLDCdEZXBhcnRtZW50IG9mIEVsZWN0cm9uaWMgVHJ1c3QgU2VydmljZXMxMjAwBgNVBAMMKSJESUlBIi4gUXVhbGlmaWVkIFRydXN0IFNlcnZpY2VzIFByb3ZpZGVyMRkwFwYDVQQFExBVQS00MzM5NTAzMy0xMTEwMQswCQYDVQQGEwJVQTENMAsGA1UEBwwES3lpdjEXMBUGA1UEYQwOTlRSVUEtNDMzOTUwMzMwHhcNMjIwNzA2MjEwMDAwWhcNMjQwNzA2MjA1OTU5WjCBtDEgMB4GA1UECgwXU3RhdGUgZW50ZXJwcmlzZSAiRElJQSIxGjAYBgNVBAMMEVNlcmhpaSBLb3NtaW5za3lpMRMwEQYDVQQEDApLb3NtaW5za3lpMQ8wDQYDVQQqDAZTZXJoaWkxGTAXBgNVBAUTEFRJTlVBLTMxNzIwMTEzNTMxCzAJBgNVBAYTAlVBMQ0wCwYDVQQHDARLeWl2MRcwFQYDVQRhDA5OVFJVQS00MzM5NTAzMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJuLYx3sca0WzRL+rP9A3R409yHCUJ25YXHxVoLkp/+yXpVzzez+dLV0As4QImqRBrihxhVgN08AG6n9GiMw3kijggJsMIICaDAdBgNVHQ4EFgQUxQr62azBDuDYo2S/YDxDY3sZgykwHwYDVR0jBBgwFoAUtHSLOUor3i9P/LHbo7XxgjSPEA4wDgYDVR0PAQH/BAQDAgZAMEkGA1UdIARCMEAwPgYJKoYkAgEBAQICMDEwLwYIKwYBBQUHAgEWI2h0dHBzOi8vY2EuaW5mb3JtanVzdC51YS9yZWdsYW1lbnQvMAkGA1UdEwQCMAAwVAYIKwYBBQUHAQMESDBGMAgGBgQAjkYBATATBgYEAI5GAQYwCQYHBACORgEGATAOBgYEAI5GAQcwBBMCVUEwFQYIKwYBBQUHCwIwCQYHBACL7EkBATBLBgNVHR8ERDBCMECgPqA8hjpodHRwOi8vY2EuaW5mb3JtanVzdC51YS9kb3dubG9hZC9jcmxzL0NBLUI0NzQ4QjM5LUZ1bGwuY3JsMEwGA1UdLgRFMEMwQaA/oD2GO2h0dHA6Ly9jYS5pbmZvcm1qdXN0LnVhL2Rvd25sb2FkL2NybHMvQ0EtQjQ3NDhCMzktRGVsdGEuY3JsMIGFBggrBgEFBQcBAQR5MHcwMgYIKwYBBQUHMAGGJmh0dHA6Ly9jYS5pbmZvcm1qdXN0LnVhL3NlcnZpY2VzL29jc3AvMEEGCCsGAQUFBzAChjVodHRwOi8vY2EuaW5mb3JtanVzdC51YS91cGxvYWRzL2NlcnRpZmljYXRlcy9kaWlhLnA3YjBHBggrBgEFBQcBCwQ7MDkwNwYIKwYBBQUHMAOGK2h0dHA6Ly9jYS5pbmZvcm1qdXN0LnVhL3NlcnZpY2VzL3RzcC9lY2RzYS8wCgYIKoZIzj0EAwIDSAAwRQIgeFeZh5I2cd03/0dZ2FoAfwI9qqZlqEMWZY9k8J31pKoCIQClSbciBvkQc/8i5o6+TLhztWYSqd8ltzQeNgzLB0Llyg==");
        eSealCertificate = DSSUtils.loadCertificateFromBase64EncodedString("MIIEQDCCA+agAwIBAgIUXpKHtb9tW+oCAAAAAQAAANEAAAAwCgYIKoZIzj0EAwIwgdExNjA0BgNVBAoMLU1pbmlzdHJ5IG9mIGRpZ2l0YWwgdHJhbnNmb3JtYXRpb24gb2YgVWtyYWluZTEeMBwGA1UECwwVQWRtaW5pc3RyYXRvciBJVFMgQ0NBMSgwJgYDVQQDDB9DZW50cmFsIGNlcnRpZmljYXRpb24gYXV0aG9yaXR5MRgwFgYDVQQFDA9VQS00MzIyMDg1MS0yNTYxCzAJBgNVBAYTAlVBMQ0wCwYDVQQHDARLeWl2MRcwFQYDVQRhDA5OVFJVQS00MzIyMDg1MTAeFw0yMDAxMjEwMzA4MDBaFw0yNTAxMjEwMzA4MDBaMIHeMTYwNAYDVQQKDC1NaW5pc3RyeSBvZiBkaWdpdGFsIHRyYW5zZm9ybWF0aW9uIG9mIFVrcmFpbmUxHjAcBgNVBAsMFUFkbWluaXN0cmF0b3IgSVRTIENDQTE0MDIGA1UEAwwrT0NTUC1zZXJ2ZXIgQ2VudHJhbCBjZXJ0aWZpY2F0aW9uIGF1dGhvcml0eTEZMBcGA1UEBQwQVUEtNDMyMjA4NTEtMjAyMDELMAkGA1UEBhMCVUExDTALBgNVBAcMBEt5aXYxFzAVBgNVBGEMDk5UUlVBLTQzMjIwODUxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7sZ2nO//6wzDZ0Gr+fMbqdxc4aYds2hk0YTJohPkLmnainmHwMytf/sEBACJRXhdToVw8YNdONCw1/n0KsosK6OCAYswggGHMB0GA1UdDgQWBBSDWEs3pLq3kZ/T2lBjeezuljxdkzAfBgNVHSMEGDAWgBRekoe1v21b6unpHaIRk+Re/FCJkTAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwkwPAYDVR0gBDUwMzAxBgkqhiQCAQEBAgIwJDAiBggrBgEFBQcCARYWaHR0cHM6Ly9jem8uZ292LnVhL2NwczAJBgNVHRMEAjAAMEQGCCsGAQUFBwEDBDgwNjAIBgYEAI5GAQEwCAYGBACORgEEMBMGBgQAjkYBBjAJBgcEAI5GAQYCMAsGCSqGJAIBAQECATBHBgNVHR8EQDA+MDygOqA4hjZodHRwOi8vY3pvLmdvdi51YS9kb3dubG9hZC9jcmxzL0NBLUVDRFNBLTIwMjAtRnVsbC5jcmwwSAYDVR0uBEEwPzA9oDugOYY3aHR0cDovL2N6by5nb3YudWEvZG93bmxvYWQvY3Jscy9DQS1FQ0RTQS0yMDIwLURlbHRhLmNybDAKBggqhkjOPQQDAgNIADBFAiBR0XnBOxsiTLnVS5mbWUSlvJtNR32Zvhstc728Y5USnQIhAOGsELbe01+t0IvAZoFLw1IvCrz6Yd64kCb7puqN/HjK");
        otherOidCertificate = DSSUtils.loadCertificateFromBase64EncodedString("MIIEyTCCBG+gAwIBAgIUXpKHtb9tW+oBAAAAAQAAAOMAAAAwCgYIKoZIzj0EAwIwgdExNjA0BgNVBAoMLU1pbmlzdHJ5IG9mIGRpZ2l0YWwgdHJhbnNmb3JtYXRpb24gb2YgVWtyYWluZTEeMBwGA1UECwwVQWRtaW5pc3RyYXRvciBJVFMgQ0NBMSgwJgYDVQQDDB9DZW50cmFsIGNlcnRpZmljYXRpb24gYXV0aG9yaXR5MRgwFgYDVQQFDA9VQS00MzIyMDg1MS0yNTYxCzAJBgNVBAYTAlVBMQ0wCwYDVQQHDARLeWl2MRcwFQYDVQRhDA5OVFJVQS00MzIyMDg1MTAeFw0yMDA2MDMwNzQzMDBaFw0yNTA2MDMwNzQzMDBaMIHYMSAwHgYDVQQKDBdTdGF0ZSBlbnRlcnByaXNlICJESUlBIjEwMC4GA1UECwwnRGVwYXJ0bWVudCBvZiBFbGVjdHJvbmljIFRydXN0IFNlcnZpY2VzMTIwMAYDVQQDDCkiRElJQSIuIFF1YWxpZmllZCBUcnVzdCBTZXJ2aWNlcyBQcm92aWRlcjEZMBcGA1UEBRMQVUEtNDMzOTUwMzMtMTExMDELMAkGA1UEBhMCVUExDTALBgNVBAcMBEt5aXYxFzAVBgNVBGEMDk5UUlVBLTQzMzk1MDMzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAER1/iqwZrmAORrFaPbwLpTaiZ5geIS6YCgZfE0Ljr3JH092E4c4It+ZvzEKE1E/g9kf0FvbjfZ38fSlZCzJDJ0qOCAhowggIWMB0GA1UdDgQWBBS0dIs5SiveL0/8sdujtfGCNI8QDjAOBgNVHQ8BAf8EBAMCAQYwPAYDVR0gBDUwMzAxBgkqhiQCAQEBAgIwJDAiBggrBgEFBQcCARYWaHR0cHM6Ly9jem8uZ292LnVhL2NwczAtBgNVHREEJjAkghBjYS5pbmZvcm1qdXN0LnVhgRBjYUBpbmZvcm1qdXN0LnVhMBIGA1UdEwEB/wQIMAYBAf8CAQAwcgYIKwYBBQUHAQMEZjBkMAgGBgQAjkYBATAIBgYEAI5GAQQwKgYGBACORgEFMCAwHhYYaHR0cHM6Ly9jem8uZ292LnVhL2Fib3V0EwJlbjAVBggrBgEFBQcLAjAJBgcEAIvsSQECMAsGCSqGJAIBAQECATAfBgNVHSMEGDAWgBRekoe1v21b6unpHaIRk+Re/FCJkTBHBgNVHR8EQDA+MDygOqA4hjZodHRwOi8vY3pvLmdvdi51YS9kb3dubG9hZC9jcmxzL0NBLUVDRFNBLTIwMjAtRnVsbC5jcmwwSAYDVR0uBEEwPzA9oDugOYY3aHR0cDovL2N6by5nb3YudWEvZG93bmxvYWQvY3Jscy9DQS1FQ0RTQS0yMDIwLURlbHRhLmNybDA8BggrBgEFBQcBAQQwMC4wLAYIKwYBBQUHMAGGIGh0dHA6Ly9jem8uZ292LnVhL3NlcnZpY2VzL29jc3AvMAoGCCqGSM49BAMCA0gAMEUCIQDjHWMxMR4ZwopSJ+1ZpahX63DgsGbrlT2j6Hg5D4924AIgdL8OrA7dpEhHbx45FqkNNS2YvcyV325GRoy0KZiO7Fw=");
    }

    @Test
    public void testQcCompliance() {
        QCStatementCondition condition = new QCStatementCondition(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance.getId(), null, null);
        assertTrue(condition.check(uaESignCertificate));
        assertTrue(condition.check(eSealCertificate));
        assertTrue(condition.check(otherOidCertificate));
    }

    @Test
    public void testESignQcType() {
        QCStatementCondition condition = new QCStatementCondition(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType.getId(), QCTypeEnum.QCT_ESIGN.getOid(), null);
        assertTrue(condition.check(uaESignCertificate));
        assertFalse(condition.check(eSealCertificate));
        assertFalse(condition.check(otherOidCertificate));
    }

    @Test
    public void testESignQcTypeAndQcCClegislation() {
        QCStatementCondition condition = new QCStatementCondition(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType.getId(), QCTypeEnum.QCT_ESIGN.getOid(), "UA");
        assertTrue(condition.check(uaESignCertificate));
        assertFalse(condition.check(eSealCertificate));
        assertFalse(condition.check(otherOidCertificate));
    }

    @Test
    public void testESealQcType() {
        QCStatementCondition condition = new QCStatementCondition(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType.getId(), QCTypeEnum.QCT_ESEAL.getOid(), null);
        assertFalse(condition.check(uaESignCertificate));
        assertTrue(condition.check(eSealCertificate));
        assertFalse(condition.check(otherOidCertificate));
    }

    @Test
    public void testESealQcTypeAndQcCClegislation() {
        QCStatementCondition condition = new QCStatementCondition(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType.getId(), QCTypeEnum.QCT_ESEAL.getOid(), "UA");
        assertFalse(condition.check(uaESignCertificate));
        assertFalse(condition.check(eSealCertificate));
        assertFalse(condition.check(otherOidCertificate));
    }

    @Test
    public void testQcQscd() {
        QCStatementCondition condition = new QCStatementCondition(ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD.getId(), null, null);
        assertFalse(condition.check(uaESignCertificate));
        assertTrue(condition.check(eSealCertificate));
        assertTrue(condition.check(otherOidCertificate));
    }

    @Test
    public void testQcPdsOid() {
        QCStatementCondition condition = new QCStatementCondition(ETSIQCObjectIdentifiers.id_etsi_qcs_QcPds.getId(), null, null);
        assertFalse(condition.check(uaESignCertificate));
        assertFalse(condition.check(eSealCertificate));
        assertTrue(condition.check(otherOidCertificate));
    }

    @Test
    public void testOtherOid() {
        QCStatementCondition condition = new QCStatementCondition("1.2.804.2.1.1.1.2.1", null, null);
        assertFalse(condition.check(uaESignCertificate));
        assertTrue(condition.check(eSealCertificate));
        assertTrue(condition.check(otherOidCertificate));
    }

}
