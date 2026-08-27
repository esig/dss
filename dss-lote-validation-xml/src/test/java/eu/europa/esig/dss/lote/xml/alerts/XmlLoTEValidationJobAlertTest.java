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
package eu.europa.esig.dss.lote.xml.alerts;

import eu.europa.esig.dss.alert.Alert;
import eu.europa.esig.dss.alert.handler.AlertHandler;
import eu.europa.esig.dss.alert.handler.CompositeAlertHandler;
import eu.europa.esig.dss.lote.alerts.LoTEAlert;
import eu.europa.esig.dss.lote.alerts.detection.LoTEParsingErrorDetection;
import eu.europa.esig.dss.lote.alerts.detection.LoTESignatureErrorDetection;
import eu.europa.esig.dss.lote.alerts.handler.log.LogLoTEParsingErrorAlertHandler;
import eu.europa.esig.dss.lote.alerts.handler.log.LogLoTESignatureErrorAlertHandler;
import eu.europa.esig.dss.lote.job.LoTEValidationJob;
import eu.europa.esig.dss.lote.source.LoTESource;
import eu.europa.esig.dss.lote.xml.MockDataLoader;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.lote.LoTEInfo;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XmlLoTEValidationJobAlertTest {

    @TempDir
    File cacheDirectory;

    private static final DSSDocument PID_PROVIDERS = new FileDocument("src/test/resources/lote-pubeaa.xml");
    private static final DSSDocument PID_PROVIDERS_BROKEN_SIG = new FileDocument("src/test/resources/lote-pubeaa-broken-sig.xml");
    private static final DSSDocument PID_PROVIDERS_NOT_PARSABLE = new FileDocument("src/test/resources/lote-pubeaa-not-parsable.xml");
    private static final DSSDocument PID_PROVIDERS_NOT_COMPLIANT = new FileDocument("src/test/resources/lote-pubeaa-not-compliant.xml");
    private static final DSSDocument PID_PROVIDERS_JSON = new FileDocument("src/test/resources/lote-pubeaa.json");

    private static CertificateToken loteSigningCertificate = DSSUtils.loadCertificateFromBase64EncodedString(
            "MIIFhjCCA26gAwIBAgIBCjANBgkqhkiG9w0BAQsFADBUMRQwEgYDVQQDDAtMb1RFLVNpZ25lcjEcMBoGA1UECgwTRVUgRGlnaXRhbCBNaW5pc3RyeTERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkVVMB4XDTE2MDEzMDEwMDgxM1oXDTM2MDEzMDEwMDgxM1owVDEUMBIGA1UEAwwLTG9URS1TaWduZXIxHDAaBgNVBAoME0VVIERpZ2l0YWwgTWluaXN0cnkxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJFVTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK5nEvkkCPKRg+ip1xX1B5HKjRYEtfflmCSUGAoSL3566u6dysdt3QWxwOkBhfMIVrGI6YxkHAiTp1mkk4WVMNdqUApeICOrpOEAC3kHWYStTrvHjuW+xyARUyzQMZ0GiQvPe5z+THL4jf94gfpGP146z6Mny9pJNJvAiGBLs1hBlW3PK6KLd0FSDp9pg/vcPtTDxh6F6d3tW2YeyJ9ZiBLx/PqYtCY5Ozzz9Md09dSiJq+xqxuFZi93QQKO0k10KrMnv0M3s7fL1Ijy9TV3tMtwhQd9lWeIRZOG+8tHSuP+bqDmnV9MDxRpZkGG9ilL4y6qa8f+64gn0MQ9r+vHlSPM5BLdHLn/JTjRrhLVIwcLahPVfGyTCi115EbVIoXZwJbsPppqnluKy0JtoUOOmonvh7GaAbAf7ouXibGDcMsorwt9lY6m6OU10v3OxZFFc6aBaIc9FNb4NgEg0meluOM7KU4Ta59bstEQCFxZR0XQzKUtEAHyC+Wyrzr0QmmwsGmXKSxQlPHNxmPFCCOc7X6+Ls37GAB0aEXddvULtLWNYqiIgwE5KgC0XnsG0do4QISrSIhoXfD8RL4LymcJCYPUHdSiiDxJGvMOGIDiOx+RUGqYLDY/mJWMH/KsgnR/M7Wm5QvtEqaFyRZOejDOFgDy8Xa+U7J8TDUDl/Jn7Tx/AgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIGwDAfBgNVHSMEGDAWgBTEksriFHLiBJcVM+bFYRY4S5T+iDAdBgNVHQ4EFgQUxJLK4hRy4gSXFTPmxWEWOEuU/ogwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAe/hSDMZIQKrENm0OeqOPDWtql5migl3XOqg3Ap9ArGxWgGIc1k3LjU62bB+M2Z1SLmQExVgX42ThMnDnH4BgsypxQEkc4ofZKJCmb+i0JBJi2hfMO96XC2S/ZJBKZuGhgxgZEkgQUtIROc8v2uS13MCVYPFmirxcS1HMF7JMC2XSEVPSh2oy7sCqtQWwkQwBfUvq/Ud1U4U50h5WpBG/bGhZ0qgRRDUzEzop2se+xqlpNql0Nf6o7TQ1zXt8oeutTGx/GZnUujuQEewEcbyQFKNh5iN/763J9PArl8uUk8kTJwRr1oxosD7w+SR8F/nuaO7XI0tB36dZm6G9+ZFaOr9vjqxYBH1D9KX6amZcAcc6LmP6jP1h0u4mVArx9vkHkwY4sffcxU8+AyoH7z3dZnbtryEyQM/0G/F1afSpZSLbEs3xaQweq1vqxjiYR5J+6mBrE9aYpZdu5qI7eFVf8UakkPPseam+quW79MzLNcpIu9eFKn0ROLzWAK6Pj/ySVo8HD76ASAX12VWtrIt8kPky8q5FYZ7VvwSerFiRUAYP11EU6hj+G3spPAxvjOY7vKDJtVrhUwH5NqRM2AABZWi5csDN05r/3bgICk1J478dZluQT7d4ExljkHlhLlI3ulVbpTyylXMJk7coENWyFL6dn+vNYdfoj3ue4mxImdM=");

    @Test
    void testSignatureErrorCatchCalled() {
        String url = "broken-sig";

        LoTEValidationJob job = new LoTEValidationJob();
        job.setLoTESources(getLoTESource(url));
        job.setOnlineDataLoader(getOnlineDataLoader(PID_PROVIDERS_BROKEN_SIG, url));

        List<Alert<LoTEInfo>> alerts = new ArrayList<>();
        LoTESignatureErrorDetection signingDetection = new LoTESignatureErrorDetection();

        CallbackAlertHandler<LoTEInfo> callback = new CallbackAlertHandler<>();
        AlertHandler<LoTEInfo> handler = new CompositeAlertHandler<>(Arrays.asList(callback, new LogLoTESignatureErrorAlertHandler()));

        LoTEAlert alert = new LoTEAlert(signingDetection, handler);
        alerts.add(alert);
        job.setDocumentAlerts(alerts);

        job.onlineRefresh();

        assertTrue(callback.called);
    }

    @Test
    void testSignatureNoErrorCatchCalled() {

        String url = "valid-doc";

        LoTEValidationJob job = new LoTEValidationJob();
        job.setLoTESources(getLoTESource(url));
        job.setOnlineDataLoader(getOnlineDataLoader(PID_PROVIDERS, url));

        List<Alert<LoTEInfo>> alerts = new ArrayList<>();
        LoTESignatureErrorDetection signingDetection = new LoTESignatureErrorDetection();

        CallbackAlertHandler<LoTEInfo> callback = new CallbackAlertHandler<>();
        AlertHandler<LoTEInfo> handler = new CompositeAlertHandler<>(Arrays.asList(callback, new LogLoTESignatureErrorAlertHandler()));

        LoTEAlert alert = new LoTEAlert(signingDetection, handler);
        alerts.add(alert);
        job.setDocumentAlerts(alerts);

        job.onlineRefresh();

        assertFalse(callback.called);
    }

    @Test
    void testParsingErrorCatchCalled() {
        String url = "not-parsable";

        LoTEValidationJob job = new LoTEValidationJob();
        job.setLoTESources(getLoTESource(url));
        job.setOnlineDataLoader(getOnlineDataLoader(PID_PROVIDERS_NOT_PARSABLE, url));

        List<Alert<LoTEInfo>> alerts = new ArrayList<>();
        LoTEParsingErrorDetection signingDetection = new LoTEParsingErrorDetection();

        CallbackAlertHandler<LoTEInfo> callback = new CallbackAlertHandler<>();
        AlertHandler<LoTEInfo> handler = new CompositeAlertHandler<>(Arrays.asList(callback, new LogLoTEParsingErrorAlertHandler()));

        LoTEAlert alert = new LoTEAlert(signingDetection, handler);
        alerts.add(alert);
        job.setDocumentAlerts(alerts);

        job.onlineRefresh();

        assertFalse(callback.called); // fails on download job
    }

    @Test
    void testParsingErrorCatchNotCalled() {
        String url = "not-parsable";

        LoTEValidationJob job = new LoTEValidationJob();
        job.setLoTESources(getLoTESource(url));
        job.setOnlineDataLoader(getOnlineDataLoader(PID_PROVIDERS_JSON, url));

        List<Alert<LoTEInfo>> alerts = new ArrayList<>();
        LoTEParsingErrorDetection signingDetection = new LoTEParsingErrorDetection();

        CallbackAlertHandler<LoTEInfo> callback = new CallbackAlertHandler<>();
        AlertHandler<LoTEInfo> handler = new CompositeAlertHandler<>(Arrays.asList(callback, new LogLoTEParsingErrorAlertHandler()));

        LoTEAlert alert = new LoTEAlert(signingDetection, handler);
        alerts.add(alert);
        job.setDocumentAlerts(alerts);

        job.onlineRefresh();

        assertFalse(callback.called);
    }

    @Test
    void testParsingNoCompliant() {
        String url = "not-compliant";

        LoTEValidationJob job = new LoTEValidationJob();
        job.setLoTESources(getLoTESource(url));
        job.setOnlineDataLoader(getOnlineDataLoader(PID_PROVIDERS_NOT_COMPLIANT, url));

        List<Alert<LoTEInfo>> alerts = new ArrayList<>();
        LoTEParsingErrorDetection signingDetection = new LoTEParsingErrorDetection();

        CallbackAlertHandler<LoTEInfo> callback = new CallbackAlertHandler<>();
        AlertHandler<LoTEInfo> handler = new CompositeAlertHandler<>(Arrays.asList(callback, new LogLoTEParsingErrorAlertHandler()));

        LoTEAlert alert = new LoTEAlert(signingDetection, handler);
        alerts.add(alert);
        job.setDocumentAlerts(alerts);

        job.onlineRefresh();

        assertTrue(callback.called);
    }

    private LoTESource getLoTESource(String url) {
        LoTESource loteSource = new LoTESource();
        loteSource.setUrl(url);
        CertificateSource certificateSource = new CommonCertificateSource();
        certificateSource.addCertificate(loteSigningCertificate);
        loteSource.setCertificateSource(certificateSource);
        return loteSource;
    }

    private DSSFileLoader getOnlineDataLoader(DSSDocument doc, String url) {
        FileCacheDataLoader onlineFileLoader = new FileCacheDataLoader();
        onlineFileLoader.setCacheExpirationTime(0);
        Map<String, DSSDocument> onlineMap = new HashMap<>();
        onlineMap.put(url, doc);
        onlineFileLoader.setDataLoader(new MockDataLoader(onlineMap));
        onlineFileLoader.setFileCacheDirectory(cacheDirectory);
        return onlineFileLoader;
    }

    private static class CallbackAlertHandler<T> implements AlertHandler<T> {

        private boolean called = false;

        @Override
        public void process(T currentInfo) {
            called = true;
        }

    }

}
