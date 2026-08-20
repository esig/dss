package eu.europa.esig.dss.lote.xml.alerts;

import eu.europa.esig.dss.alert.Alert;
import eu.europa.esig.dss.alert.handler.AlertHandler;
import eu.europa.esig.dss.alert.handler.CompositeAlertHandler;
import eu.europa.esig.dss.lote.alerts.LoTEAlert;
import eu.europa.esig.dss.lote.alerts.detection.LoTESequenceNumberErrorDetection;
import eu.europa.esig.dss.lote.alerts.handler.log.LogLoTESequenceNumberErrorAlertHandler;
import eu.europa.esig.dss.lote.job.LoTEValidationJob;
import eu.europa.esig.dss.lote.xml.MockDataLoader;
import eu.europa.esig.dss.lote.source.LoTESource;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.lote.LoTEInfo;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.lote.TrustedEntitiesCertificateSource;
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

class XmlLoTESequenceNumberAlertTest {

    private static final String PUBEAA_URL = "pubeaa";

    private static final DSSDocument PUBEAA = new FileDocument("src/test/resources/lote-pubeaa.xml");
    private static final DSSDocument PUBEAA_ALTERED = new FileDocument("src/test/resources/lote-pubeaa-broken-sig.xml");
    private static final DSSDocument PUBEAA_2 = new FileDocument("src/test/resources/lote-pubeaa-sn2.xml");

    private static final Map<String, DSSDocument> onlineMap = new HashMap<>();

    @TempDir
    File cacheDirectory;

    @Test
    void testIncrement() {
        updateDocument(PUBEAA_URL, PUBEAA);

        LoTEValidationJob job = getLoTEValidationJob();

        List<Alert<LoTEInfo>> alerts = new ArrayList<>();
        LoTESequenceNumberErrorDetection tslSequenceNumberDetection = new LoTESequenceNumberErrorDetection();

        CallbackAlertHandler<LoTEInfo> callback = new CallbackAlertHandler<>();
        AlertHandler<LoTEInfo> handler = new CompositeAlertHandler<>(Arrays.asList(callback, new LogLoTESequenceNumberErrorAlertHandler()));

        LoTEAlert alert = new LoTEAlert(tslSequenceNumberDetection, handler);
        alerts.add(alert);
        job.setDocumentAlerts(alerts);

        job.onlineRefresh();

        assertFalse(callback.called); // original

        job.onlineRefresh();

        assertFalse(callback.called); // no change

        updateDocument(PUBEAA_URL, PUBEAA_2);
        job.onlineRefresh();

        assertFalse(callback.called); // valid increment
    }

    @Test
    void testDecrement() {
        updateDocument(PUBEAA_URL, PUBEAA_2);

        LoTEValidationJob job = getLoTEValidationJob();

        List<Alert<LoTEInfo>> alerts = new ArrayList<>();
        LoTESequenceNumberErrorDetection tslSequenceNumberDetection = new LoTESequenceNumberErrorDetection();

        CallbackAlertHandler<LoTEInfo> callback = new CallbackAlertHandler<>();
        AlertHandler<LoTEInfo> handler = new CompositeAlertHandler<>(Arrays.asList(callback, new LogLoTESequenceNumberErrorAlertHandler()));

        LoTEAlert alert = new LoTEAlert(tslSequenceNumberDetection, handler);
        alerts.add(alert);
        job.setDocumentAlerts(alerts);

        job.onlineRefresh();

        assertFalse(callback.called); // original

        updateDocument(PUBEAA_URL, PUBEAA);
        job.onlineRefresh();

        assertTrue(callback.called); // decrement
    }

    @Test
    void testUpdateSameNumber() {
        updateDocument(PUBEAA_URL, PUBEAA_ALTERED);

        LoTEValidationJob job = getLoTEValidationJob();

        List<Alert<LoTEInfo>> alerts = new ArrayList<>();
        LoTESequenceNumberErrorDetection tslSequenceNumberDetection = new LoTESequenceNumberErrorDetection();

        CallbackAlertHandler<LoTEInfo> callback = new CallbackAlertHandler<>();
        AlertHandler<LoTEInfo> handler = new CompositeAlertHandler<>(Arrays.asList(callback, new LogLoTESequenceNumberErrorAlertHandler()));

        LoTEAlert alert = new LoTEAlert(tslSequenceNumberDetection, handler);
        alerts.add(alert);
        job.setDocumentAlerts(alerts);

        job.onlineRefresh();

        assertFalse(callback.called); // original

        updateDocument(PUBEAA_URL, PUBEAA);
        job.onlineRefresh();

        assertTrue(callback.called); // same
    }

    private LoTEValidationJob getLoTEValidationJob() {
        LoTEValidationJob job = new LoTEValidationJob();
        job.setTrustedEntitiesCertificateSource(new TrustedEntitiesCertificateSource());
        job.setOnlineDataLoader(getOnlineDataLoader());
        job.setLoTESources(getLoTESource(PUBEAA_URL));
        return job;
    }

    private LoTESource getLoTESource(String url) {
        LoTESource loteSource = new LoTESource();
        loteSource.setUrl(url);
        CertificateSource certificateSource = new CommonCertificateSource();
        certificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
                "MIIFhjCCA26gAwIBAgIBCjANBgkqhkiG9w0BAQsFADBUMRQwEgYDVQQDDAtMb1RFLVNpZ25lcjEcMBoGA1UECgwTRVUgRGlnaXRhbCBNaW5pc3RyeTERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkVVMB4XDTE2MDEzMDEwMDgxM1oXDTM2MDEzMDEwMDgxM1owVDEUMBIGA1UEAwwLTG9URS1TaWduZXIxHDAaBgNVBAoME0VVIERpZ2l0YWwgTWluaXN0cnkxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJFVTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK5nEvkkCPKRg+ip1xX1B5HKjRYEtfflmCSUGAoSL3566u6dysdt3QWxwOkBhfMIVrGI6YxkHAiTp1mkk4WVMNdqUApeICOrpOEAC3kHWYStTrvHjuW+xyARUyzQMZ0GiQvPe5z+THL4jf94gfpGP146z6Mny9pJNJvAiGBLs1hBlW3PK6KLd0FSDp9pg/vcPtTDxh6F6d3tW2YeyJ9ZiBLx/PqYtCY5Ozzz9Md09dSiJq+xqxuFZi93QQKO0k10KrMnv0M3s7fL1Ijy9TV3tMtwhQd9lWeIRZOG+8tHSuP+bqDmnV9MDxRpZkGG9ilL4y6qa8f+64gn0MQ9r+vHlSPM5BLdHLn/JTjRrhLVIwcLahPVfGyTCi115EbVIoXZwJbsPppqnluKy0JtoUOOmonvh7GaAbAf7ouXibGDcMsorwt9lY6m6OU10v3OxZFFc6aBaIc9FNb4NgEg0meluOM7KU4Ta59bstEQCFxZR0XQzKUtEAHyC+Wyrzr0QmmwsGmXKSxQlPHNxmPFCCOc7X6+Ls37GAB0aEXddvULtLWNYqiIgwE5KgC0XnsG0do4QISrSIhoXfD8RL4LymcJCYPUHdSiiDxJGvMOGIDiOx+RUGqYLDY/mJWMH/KsgnR/M7Wm5QvtEqaFyRZOejDOFgDy8Xa+U7J8TDUDl/Jn7Tx/AgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIGwDAfBgNVHSMEGDAWgBTEksriFHLiBJcVM+bFYRY4S5T+iDAdBgNVHQ4EFgQUxJLK4hRy4gSXFTPmxWEWOEuU/ogwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAe/hSDMZIQKrENm0OeqOPDWtql5migl3XOqg3Ap9ArGxWgGIc1k3LjU62bB+M2Z1SLmQExVgX42ThMnDnH4BgsypxQEkc4ofZKJCmb+i0JBJi2hfMO96XC2S/ZJBKZuGhgxgZEkgQUtIROc8v2uS13MCVYPFmirxcS1HMF7JMC2XSEVPSh2oy7sCqtQWwkQwBfUvq/Ud1U4U50h5WpBG/bGhZ0qgRRDUzEzop2se+xqlpNql0Nf6o7TQ1zXt8oeutTGx/GZnUujuQEewEcbyQFKNh5iN/763J9PArl8uUk8kTJwRr1oxosD7w+SR8F/nuaO7XI0tB36dZm6G9+ZFaOr9vjqxYBH1D9KX6amZcAcc6LmP6jP1h0u4mVArx9vkHkwY4sffcxU8+AyoH7z3dZnbtryEyQM/0G/F1afSpZSLbEs3xaQweq1vqxjiYR5J+6mBrE9aYpZdu5qI7eFVf8UakkPPseam+quW79MzLNcpIu9eFKn0ROLzWAK6Pj/ySVo8HD76ASAX12VWtrIt8kPky8q5FYZ7VvwSerFiRUAYP11EU6hj+G3spPAxvjOY7vKDJtVrhUwH5NqRM2AABZWi5csDN05r/3bgICk1J478dZluQT7d4ExljkHlhLlI3ulVbpTyylXMJk7coENWyFL6dn+vNYdfoj3ue4mxImdM="));
        loteSource.setCertificateSource(certificateSource);
        return loteSource;
    }

    private DSSFileLoader getOnlineDataLoader() {
        FileCacheDataLoader onlineFileLoader = new FileCacheDataLoader();
        onlineFileLoader.setCacheExpirationTime(0);
        onlineFileLoader.setDataLoader(new MockDataLoader(onlineMap));
        onlineFileLoader.setFileCacheDirectory(cacheDirectory);
        return onlineFileLoader;
    }

    private void updateDocument(String url, DSSDocument dssDocument) {
        onlineMap.put(url, dssDocument);
    }
    
}
