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
package eu.europa.esig.dss.tsl.validation;

import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.MemoryDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SKCertificateTest {

    private static final DSSDocument TL_DOC = new FileDocument(new File("src/test/resources/sk-tl-sn-95.xml"));

    private static final String SK_TL_URL = "sk-tl.xml";

    private static final CertificateToken TL_ISSUER = DSSUtils.loadCertificateFromBase64EncodedString(
            "MIIGWjCCBEKgAwIBAgICCFgwDQYJKoZIhvcNAQELBQAwbTELMAkGA1UEBhMCU0sxEzARBgNVBAcMCkJyYXRpc2xhdmExIjAgBgNVBAoMGU5hcm9kbnkgYmV6cGVjbm9zdG55IHVyYWQxDjAMBgNVBAsMBVNJQkVQMRUwEwYDVQQDDAxLQ0EgTkJVIFNSIDMwHhcNMTkwMjE1MTMyNTIzWhcNMjMwMjE1MTMyNDIxWjCBjTELMAkGA1UEBhMCU0sxEzARBgNVBAcMCkJyYXRpc2xhdmExJzAlBgNVBAoMHk7DoXJvZG7DvSBiZXpwZcSNbm9zdG7DvSDDunJhZDEnMCUGA1UEAwweVEwgYW5kIFNpZ25hdHVyZSBQb2xpY3kgTGlzdCA2MRcwFQYDVQQFEw5OVFJTSy0zNjA2MTcwMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ57HgI4/bNV919cbGCKndQkz7MX/QhdhDmTYIQqOhadsB3FCkBqQ1ato7xhU4kVmuA3d0dHJB/fGbuhSbC6K39EHubw6UOLXZdX6qmvcqQRLPEyw76rL/UWhK6T2N3dJ9VvjbtFcaT5cGhmbdw7mcY13pTIxfYlEdrH3xx9M4C6ZQaztphdOcmbP73XH9iTlPg+sVLu+Zfgs0hhBhMnRA4OdN8L/FILOwyxCM8bxanH1JnQr0+y+gcfrhMLCq12p7yJxP/asI4UlDex0NI6+xlVK6BUpY9RfyeJnbRE/Z8fcGefS3HQmo0EkLKuc0CuEEXOJaRdvTShM5eiaooIxkUCAwEAAaOCAeEwggHdMAkGA1UdEwQCMAAwYgYDVR0gBFswWTBFBg0rgR6RmYQFAAAAAQICMDQwMgYIKwYBBQUHAgEWJmh0dHA6Ly9lcC5uYnVzci5zay9rY2EvZG9jL2tjYV9jcHMucGRmMBAGDiuBHpGZhAUAAAEKBQABMFEGCCsGAQUFBwEBBEUwQzBBBggrBgEFBQcwAoY1aHR0cDovL2VwLm5idS5nb3Yuc2sva2NhL2NlcnRzL2tjYTMva2NhbmJ1c3IzX3A3Yy5wN2MweQYDVR0RBHIwcIEUcG9kYXRlbG5hQG5idS5nb3Yuc2uGWGh0dHA6Ly93d3cubmJ1Lmdvdi5zay9lbi90cnVzdC1zZXJ2aWNlcy90cnVzdC1pbmZyYXN0cnVjdHVyZS9zaWduYXR1cmUtcG9saWN5L2luZGV4Lmh0bWwwDgYDVR0PAQH/BAQDAgZAMBEGA1UdJQQKMAgGBgQAkTcDADAfBgNVHSMEGDAWgBR/8T0hwpdaLpcHDrFpgyX9IYY+BzA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8vZXAubmJ1c3Iuc2sva2NhL2NybHMzL2tjYW5idXNyMy5jcmwwHQYDVR0OBBYEFDeKMaYlumCadIoYElk/V1ef1Wu5MA0GCSqGSIb3DQEBCwUAA4ICAQAmCMjhuzK6EerM1i2Nnn7LPmzqQJzPRuKwBDa4QI9lHczj8us8md5i0zAyla61lMmw4tCWPPaASg053MD90Z1rRU4/17rX7FRdZz1wbD2zp5bKE8/pNSI4rR97S69seu6WnJOz+zGJnhgKb4Knt3T+PAac9ObGQIbFbDLxGf4HKjjSwqT36EKpyuuLQhliC8wH5Sl3yKFC9K5j5SeAEoYNTJDd8X4HJHf1OY9TZ6awY09r6qWdsaC+YiOpDt1lDok8Sq0gwzAznPjQOTNwCkHIS9I7NjvVBU6Yi3bH7ObAj5dp8XAD8uOyWEPs6w3zyxmgIInftn32GxQqsRNZlWbVXziXS2amWpZIcu9hZdENQJ57N8Zvcwhm1EvRkwUh+pskWQHi2JV9Ow9i5sCURmyY4nK28/aMN/RvlUhAlr6BKAxMoYdoOESg26gcMDrqidIGwUTg6dEWdO8dGTAondUsh8SVcxCpy1k1yYXe18jG+ksRjbbET9SToSxSNbg9k4DAor2QxO7Y1UL1TEB4lX2hkkLIVPE0DN90FEge2CmDU+ZsDRYo4HttO8iDU7hGX8SQqMT0dPu2ZhQ0Azf65Q/q9/P1QWcCA2zLW9hvcroXj4zhI3GqiYC0EmbB6tmsOnlGFZRzRQtLQPeyQyFKaD4LTnAoPFNeCmhVYG0piKRNJg==");

    private static final CertificateToken CERTIFICATE = DSSUtils.loadCertificateFromBase64EncodedString(
            "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");

    @Test
    void skTLTest() throws Exception {
        CommonCertificateSource certificateSource = new CommonCertificateSource();
        certificateSource.addCertificate(TL_ISSUER);

        TLValidationJob tlValidationJob = new TLValidationJob();

        TLSource tlSource = new TLSource();
        tlSource.setUrl(SK_TL_URL);
        tlSource.setCertificateSource(certificateSource);
        tlValidationJob.setTrustedListSources(tlSource);

        Map<String, byte[]> tlMap = new HashMap<>();
        tlMap.put(SK_TL_URL, DSSUtils.toByteArray(TL_DOC));
        MemoryDataLoader memoryDataLoader = new MemoryDataLoader(tlMap);

        FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader();
        fileCacheDataLoader.setDataLoader(memoryDataLoader);
        fileCacheDataLoader.setCacheExpirationTime(0);
        tlValidationJob.setOfflineDataLoader(fileCacheDataLoader);

        TrustedListsCertificateSource trustedCertificateSource = new TrustedListsCertificateSource();
        tlValidationJob.setTrustedListCertificateSource(trustedCertificateSource);

        tlValidationJob.offlineRefresh();

        assertEquals(214, trustedCertificateSource.getCertificates().size());

        CertificateValidator certificateValidator = CertificateValidator.fromCertificate(CERTIFICATE);
        CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        certificateVerifier.setTrustedCertSources(trustedCertificateSource);
        certificateValidator.setCertificateVerifier(certificateVerifier);

        CertificateReports reports = certificateValidator.validate();
        SimpleCertificateReport simpleReport = reports.getSimpleReport();

        assertEquals(Indication.PASSED, simpleReport.getCertificateIndication(CERTIFICATE.getDSSIdAsString()));
        assertEquals(CertificateQualification.CERT_FOR_UNKNOWN, simpleReport.getQualificationAtCertificateIssuance());
    }

}
