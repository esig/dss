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
package eu.europa.esig.dss.lote.json.alerts;

import eu.europa.esig.dss.alert.Alert;
import eu.europa.esig.dss.alert.handler.AlertHandler;
import eu.europa.esig.dss.alert.handler.CompositeAlertHandler;
import eu.europa.esig.dss.lote.alerts.LoTEAlert;
import eu.europa.esig.dss.lote.alerts.detection.LoTEParsingErrorDetection;
import eu.europa.esig.dss.lote.alerts.detection.LoTESignatureErrorDetection;
import eu.europa.esig.dss.lote.alerts.handler.log.LogLoTEParsingErrorAlertHandler;
import eu.europa.esig.dss.lote.alerts.handler.log.LogLoTESignatureErrorAlertHandler;
import eu.europa.esig.dss.lote.job.LoTEValidationJob;
import eu.europa.esig.dss.lote.json.MockDataLoader;
import eu.europa.esig.dss.lote.source.LoTESource;
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

class JsonLoTEValidationJobAlertTest {

    @TempDir
    File cacheDirectory;

    private static final DSSDocument PID_PROVIDERS = new FileDocument("src/test/resources/pid-providers.json");
    private static final DSSDocument PID_PROVIDERS_BROKEN_SIG = new FileDocument("src/test/resources/pid-providers-broken-sig.json");
    private static final DSSDocument PID_PROVIDERS_NOT_PARSABLE = new FileDocument("src/test/resources/pid-providers-broken-json.json");
    private static final DSSDocument PID_PROVIDERS_NOT_COMPLIANT = new FileDocument("src/test/resources/pid-providers-not-compliant.json");
    private static final DSSDocument PID_PROVIDERS_JSON_SERIALIZATION = new FileDocument("src/test/resources/pid-providers-json-serialization.json");

    private static CertificateToken loteSigningCertificate = DSSUtils.loadCertificateFromBase64EncodedString(
            "MIIGzzCCBLegAwIBAgIDCx7mMA0GCSqGSIb3DQEBCwUAMDcxHDAaBgNVBAoME0V1cm9wZWFuIENvbW1pc3Npb24xFzAVBgNVBAMMDkNvbW1pc1NpZ24gLSAyMB4XDTI1MTEyMDA5MzEyNloXDTI4MTEyMDA5MzEyNlowgZcxCzAJBgNVBAYTAkxVMRIwEAYDVQQLDAlESUdJVC5CLjMxHDAaBgNVBAoME0V1cm9wZWFuIENvbW1pc3Npb24xMzAxBgkqhkiG9w0BCQEWJERJR0lULUVVLVRSVVNULU5PTi1QUk9EQGVjLmV1cm9wYS5ldTEhMB8GA1UEAwwYVEVTVCBFdXJvcGVhbiBDb21taXNzaW9uMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAkij7bkMVg45Ki0zqbrxJNOo7PoHp6EQrs5/qKEFzu6mTvow550P06NmaeTonfxa/504EiQuTksosupku+MPSF9oAmbo5ezlz43UWFY3IBWI4EEnmemoakY4ZZcSiNxDN7zkts2mlQAIkc6QDFA/e624yF+UiCLpbsyMWYmez2bYMMduO+bnD7pztGZPgih9yzYK7efeZ2LgNd3+jWCtBXr4/+91XA1F0IEuxTN/Yu20uO4yA4dL/+6or+pQfG96kpyLJMaliblJ7/8lBe8h3jM1BpbrodomjncHTbvBO+TlanZhvEMcp4dFaYu3OODqQ1NP+lo8g1fr80N8pL3wuI4TC3XqAjCG54bW8dzqrilT4RDapVrWFWWp8YzftkidYffoyXacrxtSSGQ3mQvMtUOk8JPl9NlrEAe2dIGRVuMj4gu4XCgeC3nQbp6SKJTsUO7K4RJl5ODc1gvwT+1LULDGLGkaCjP4bTSK3lKVjijWn3EivplbnmUmL2pWvb9RqIvvmHIMOwnhmzikF35R1HnCuyJISU1EcFcWq/CJAFfo09HiWcitjACSsluQIshGDFEKwMtCujSjgY22dENXejxi1whxY2bDF/X353eQGD4GwU1FIQEmXwUP0zSch/8ktCo6wulN3VV4DQNRw61aAErqSi5Ji+0oLsiuogR4hvzMCAwEAAaOCAYEwggF9MB0GA1UdDgQWBBQOq28wkzABsoIf+BBH5oJqgTQP+jAfBgNVHSMEGDAWgBSa+492ZpjcrCzXdzZxbbrjZ0eR9jAOBgNVHQ8BAf8EBAMCBkAwLwYDVR0RBCgwJoEkRElHSVQtRVUtVFJVU1QtTk9OLVBST0RAZWMuZXVyb3BhLmV1MCMGCCsGAQUFBwEDBBcwFTATBgYEAI5GAQYwCQYHBACORgEGAjBJBgNVHR8EQjBAMD6gPKA6hjhodHRwOi8vY29tbWlzc2lnbi5wa2kuZWMuZXVyb3BhLmV1L2luZm8vY3JsL29ubGluZUNBLmNybDCBiQYIKwYBBQUHAQEEfTB7MEQGCCsGAQUFBzAChjhodHRwOi8vY29tbWlzc2lnbi5wa2kuZWMuZXVyb3BhLmV1L2luZm8vYWlhL29ubGluZUNBLmNydDAzBggrBgEFBQcwAYYnaHR0cDovL2NvbW1pc3NpZ24ucGtpLmVjLmV1cm9wYS5ldS9vY3NwMA0GCSqGSIb3DQEBCwUAA4ICAQCVp/Sw2OcDCaGitFGP3zoyjiOzTPjf/or5KwwZ6P2opbSOdD8M9h05QlXPjeE/29JeJ/B1I0ZhBEXsrg69JB7iLqsm+3TDDhZ7m6DkMuImmeW5ihMp+E28a20ndFnDIj//XI8F41oJBw0/2Uy/yXloAIXx8o6UeItSI3pe3mV5cU02XmIfql80nBmK9vy14ZXbKeMRpAHH0GD8CWzM00+pyzzbQFuYNm/JrjmlrfNJmBUUwtZm8G9nDQBI7kcl7TbFKcllQJ5H0G00y46U+1ytE7r76aramBmbHhCmSWWqO8y/54Z+R/SdAt1mK4dZIXyB02aEg9KGMiNlQwfKgLYazlTU/KxJnjBoRYWKfPDJoRAdMaFk3gRJNij50ZENOb2zpaH0WF/0BHB+84umyQ09ILoTEPlFESo6Y5MBUENVLnYR50rmBTfKky0I3P+KGXuMvfPZc8ZB6ID5IIqi/2LiN6swwPGGq8s5YAC9cYjIQsV3wIhFG8FoGS4zNT8qa2eIp6WFYxjrGOelrp1Uv0eYZaCcKo0KATBvxWalRypA5cdyyGTXBchiElpEgVnIUc0VKPyrCpY+N1rgdSD8DOMSixluG17QElAxdOFv/zrHisakj1Lw+AgRyErOopC625I65Tb3EM9GNqSHXuWpMmfzZSoYeOr+5g22edP5vvDjuZYg==");

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

        assertTrue(callback.called);
    }

    @Test
    void testParsingErrorCatchNotCalled() {
        String url = "not-parsable";

        LoTEValidationJob job = new LoTEValidationJob();
        job.setLoTESources(getLoTESource(url));
        job.setOnlineDataLoader(getOnlineDataLoader(PID_PROVIDERS_JSON_SERIALIZATION, url));

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

}
