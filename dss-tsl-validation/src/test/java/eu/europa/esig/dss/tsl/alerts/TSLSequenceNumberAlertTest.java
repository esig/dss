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
package eu.europa.esig.dss.tsl.alerts;

import eu.europa.esig.dss.alert.Alert;
import eu.europa.esig.dss.alert.handler.AlertHandler;
import eu.europa.esig.dss.alert.handler.CompositeAlertHandler;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.tsl.TLInfo;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.tsl.alerts.detections.TSLSequenceNumberErrorDetection;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTSLSequenceNumberErrorAlertHandler;
import eu.europa.esig.dss.tsl.job.MockDataLoader;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.TLSource;
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

class TSLSequenceNumberAlertTest {

    private static final String SK_URL = "sk-trusted-list";
    private static final String SK_URL_ALT = "sk-trusted-list-alt";

    private static final DSSDocument SK = new FileDocument("src/test/resources/sk-tl.xml");
    private static final DSSDocument SK_ALTERED = new FileDocument("src/test/resources/sk-tl-altered-trust-service.xml");
    private static final DSSDocument SK_95 = new FileDocument("src/test/resources/sk-tl-sn-95.xml");

    private static final DSSDocument FI = new FileDocument("src/test/resources/fi-v5.xml");

    private static final Map<String, DSSDocument> onlineMap = new HashMap<>();

    @TempDir
    File cacheDirectory;

    @Test
    void testIncrement() {
        updateDocument(SK_URL, SK);

        TLValidationJob job = getTLValidationJob();

        List<Alert<TLInfo>> alerts = new ArrayList<>();
        TSLSequenceNumberErrorDetection tslSequenceNumberDetection = new TSLSequenceNumberErrorDetection();

        CallbackAlertHandler<TLInfo> callback = new CallbackAlertHandler<>();
        AlertHandler<TLInfo> handler = new CompositeAlertHandler<>(Arrays.asList(callback, new LogTSLSequenceNumberErrorAlertHandler()));

        TLAlert alert = new TLAlert(tslSequenceNumberDetection, handler);
        alerts.add(alert);
        job.setTLAlerts(alerts);

        job.onlineRefresh();

        assertFalse(callback.called); // original

        job.onlineRefresh();

        assertFalse(callback.called); // no change

        updateDocument(SK_URL, SK_95);
        job.onlineRefresh();

        assertFalse(callback.called); // valid increment
    }

    @Test
    void testDecrement() {
        updateDocument(SK_URL, SK_95);

        TLValidationJob job = getTLValidationJob();

        List<Alert<TLInfo>> alerts = new ArrayList<>();
        TSLSequenceNumberErrorDetection tslSequenceNumberDetection = new TSLSequenceNumberErrorDetection();

        CallbackAlertHandler<TLInfo> callback = new CallbackAlertHandler<>();
        AlertHandler<TLInfo> handler = new CompositeAlertHandler<>(Arrays.asList(callback, new LogTSLSequenceNumberErrorAlertHandler()));

        TLAlert alert = new TLAlert(tslSequenceNumberDetection, handler);
        alerts.add(alert);
        job.setTLAlerts(alerts);

        job.onlineRefresh();

        assertFalse(callback.called); // original

        updateDocument(SK_URL, SK);
        job.onlineRefresh();

        assertTrue(callback.called); // decrement
    }

    @Test
    void testUpdateSameNumber() {
        updateDocument(SK_URL, SK_ALTERED);

        TLValidationJob job = getTLValidationJob();

        List<Alert<TLInfo>> alerts = new ArrayList<>();
        TSLSequenceNumberErrorDetection tslSequenceNumberDetection = new TSLSequenceNumberErrorDetection();

        CallbackAlertHandler<TLInfo> callback = new CallbackAlertHandler<>();
        AlertHandler<TLInfo> handler = new CompositeAlertHandler<>(Arrays.asList(callback, new LogTSLSequenceNumberErrorAlertHandler()));

        TLAlert alert = new TLAlert(tslSequenceNumberDetection, handler);
        alerts.add(alert);
        job.setTLAlerts(alerts);

        job.onlineRefresh();

        assertFalse(callback.called); // original

        updateDocument(SK_URL, SK);
        job.onlineRefresh();

        assertTrue(callback.called); // same
    }

    @Test
    void testNewLocationNoChange() {
        updateDocument(SK_URL, SK);

        TLValidationJob job = getTLValidationJob();

        List<Alert<TLInfo>> alerts = new ArrayList<>();
        TSLSequenceNumberErrorDetection tslSequenceNumberDetection = new TSLSequenceNumberErrorDetection();

        CallbackAlertHandler<TLInfo> callback = new CallbackAlertHandler<>();
        AlertHandler<TLInfo> handler = new CompositeAlertHandler<>(Arrays.asList(callback, new LogTSLSequenceNumberErrorAlertHandler()));

        TLAlert alert = new TLAlert(tslSequenceNumberDetection, handler);
        alerts.add(alert);
        job.setTLAlerts(alerts);

        job.onlineRefresh();

        assertFalse(callback.called); // original

        job.setTrustedListSources(getTLSource(SK_URL_ALT));
        updateDocument(SK_URL_ALT, SK);

        job.onlineRefresh();

        assertFalse(callback.called); // no change
    }

    @Test
    void testNewLocationChange() {
        updateDocument(SK_URL, SK_95);

        TLValidationJob job = getTLValidationJob();

        List<Alert<TLInfo>> alerts = new ArrayList<>();
        TSLSequenceNumberErrorDetection tslSequenceNumberDetection = new TSLSequenceNumberErrorDetection();

        CallbackAlertHandler<TLInfo> callback = new CallbackAlertHandler<>();
        AlertHandler<TLInfo> handler = new CompositeAlertHandler<>(Arrays.asList(callback, new LogTSLSequenceNumberErrorAlertHandler()));

        TLAlert alert = new TLAlert(tslSequenceNumberDetection, handler);
        alerts.add(alert);
        job.setTLAlerts(alerts);

        job.onlineRefresh();

        assertFalse(callback.called); // original

        job.setTrustedListSources(getTLSource(SK_URL_ALT));
        updateDocument(SK_URL_ALT, SK);

        job.onlineRefresh();

        assertTrue(callback.called);
    }

    @Test
    void testOtherTL() {
        updateDocument(SK_URL, SK);

        TLValidationJob job = getTLValidationJob();

        List<Alert<TLInfo>> alerts = new ArrayList<>();
        TSLSequenceNumberErrorDetection tslSequenceNumberDetection = new TSLSequenceNumberErrorDetection();

        CallbackAlertHandler<TLInfo> callback = new CallbackAlertHandler<>();
        AlertHandler<TLInfo> handler = new CompositeAlertHandler<>(Arrays.asList(callback, new LogTSLSequenceNumberErrorAlertHandler()));

        TLAlert alert = new TLAlert(tslSequenceNumberDetection, handler);
        alerts.add(alert);
        job.setTLAlerts(alerts);

        job.onlineRefresh();

        assertFalse(callback.called); // original

        job.setTrustedListSources(getTLSource(SK_URL_ALT));
        updateDocument(SK_URL_ALT, FI);

        job.onlineRefresh();

        assertFalse(callback.called); // no URL or CC match
    }

    private TLValidationJob getTLValidationJob() {
        TLValidationJob job = new TLValidationJob();
        job.setTrustedListCertificateSource(new TrustedListsCertificateSource());
        job.setOnlineDataLoader(getOnlineDataLoader());
        job.setTrustedListSources(getTLSource(SK_URL));
        return job;
    }

    private TLSource getTLSource(String url) {
        TLSource tlSource = new TLSource();
        tlSource.setUrl(url);
        CertificateSource certificateSource = new CommonCertificateSource();
        certificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
                "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"));
        tlSource.setCertificateSource(certificateSource);
        return tlSource;
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
