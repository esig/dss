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
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.model.tsl.LOTLInfo;
import eu.europa.esig.dss.model.tsl.TLInfo;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.tsl.alerts.detections.LOTLLocationChangeDetection;
import eu.europa.esig.dss.tsl.alerts.detections.OJUrlChangeDetection;
import eu.europa.esig.dss.tsl.alerts.detections.TLExpirationDetection;
import eu.europa.esig.dss.tsl.alerts.detections.TLParsingErrorDetection;
import eu.europa.esig.dss.tsl.alerts.detections.TLSignatureErrorDetection;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogLOTLLocationChangeAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogOJUrlChangeAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTLExpirationAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTLParsingErrorAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTLSignatureErrorAlertHandler;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.job.MockDataLoader;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
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

@SuppressWarnings({ "rawtypes", "unchecked" })
class TLValidationJobAlertTest {

	@TempDir
	File cacheDirectory;

	private static final DSSDocument CZ = new FileDocument("src/test/resources/lotlCache/CZ.xml");
	private static final DSSDocument CZ_BROKEN_SIG = new FileDocument("src/test/resources/lotlCache/CZ_broken-sig.xml");
	private static final DSSDocument CZ_NOT_PARSABLE = new FileDocument("src/test/resources/lotlCache/CZ_not-compliant.xml");

	private static final DSSDocument LOTL = new FileDocument("src/test/resources/lotlCache/tl_pivot_247_mp.xml");
	private static final String LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";
	private static final String OLD_LOTL_URL = "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml";
	private static final DSSDocument EXPIRED_LOTL = new FileDocument(
			"src/test/resources/lotlCache/tl_pivot_172_mp.xml");

	private static CertificateToken lotlSigningCertificate = DSSUtils.loadCertificateFromBase64EncodedString(
			"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");

	@Test
	void testSignatureErrorCatchCalled() {
		String url = "broken-sig";

		TLValidationJob job = new TLValidationJob();
		job.setTrustedListSources(getTLSource(url));
		job.setOnlineDataLoader(getOnlineDataLoader(CZ_BROKEN_SIG, url));

		List<Alert<TLInfo>> alerts = new ArrayList<>();
		TLSignatureErrorDetection signingDetection = new TLSignatureErrorDetection();

		CallbackAlertHandler callback = new CallbackAlertHandler();
		AlertHandler<TLInfo> handler = new CompositeAlertHandler<TLInfo>(Arrays.asList(callback, new LogTLSignatureErrorAlertHandler()));

		TLAlert alert = new TLAlert(signingDetection, handler);
		alerts.add(alert);
		job.setTLAlerts(alerts);

		job.onlineRefresh();

		assertTrue(callback.called);
	}

	@Test
	void testSignatureNoErrorCatchCalled() {

		String url = "valid-doc";

		TLValidationJob job = new TLValidationJob();
		job.setTrustedListSources(getTLSource(url));
		job.setOnlineDataLoader(getOnlineDataLoader(CZ, url));

		List<Alert<TLInfo>> alerts = new ArrayList<>();
		TLSignatureErrorDetection signingDetection = new TLSignatureErrorDetection();

		CallbackAlertHandler callback = new CallbackAlertHandler();
		AlertHandler<TLInfo> handler = new CompositeAlertHandler<TLInfo>(Arrays.asList(callback, new LogTLSignatureErrorAlertHandler()));

		TLAlert alert = new TLAlert(signingDetection, handler);
		alerts.add(alert);
		job.setTLAlerts(alerts);

		job.onlineRefresh();

		assertFalse(callback.called);
	}

	@Test
	void testParsingErrorCatchCalled() {
		String url = "not-parsable";

		TLValidationJob job = new TLValidationJob();
		job.setTrustedListSources(getTLSource(url));
		job.setOnlineDataLoader(getOnlineDataLoader(CZ_NOT_PARSABLE, url));

		List<Alert<TLInfo>> alerts = new ArrayList<>();
		TLParsingErrorDetection signingDetection = new TLParsingErrorDetection();

		CallbackAlertHandler callback = new CallbackAlertHandler();
		AlertHandler<TLInfo> handler = new CompositeAlertHandler<TLInfo>(Arrays.asList(callback, new LogTLParsingErrorAlertHandler()));

		TLAlert alert = new TLAlert(signingDetection, handler);
		alerts.add(alert);
		job.setTLAlerts(alerts);

		job.onlineRefresh();

		assertTrue(callback.called);
	}

	@Test
	void testExpirationDetectionCatchCalled() {
		String url = "valid-doc";

		TLValidationJob job = new TLValidationJob();
		job.setTrustedListSources(getTLSource(url));
		job.setOnlineDataLoader(getOnlineDataLoader(EXPIRED_LOTL, url));

		List<Alert<TLInfo>> alerts = new ArrayList<>();
		TLExpirationDetection expirationDetection = new TLExpirationDetection();

		CallbackAlertHandler callback = new CallbackAlertHandler();
		AlertHandler<TLInfo> handler = new CompositeAlertHandler<TLInfo>(Arrays.asList(callback, new LogTLExpirationAlertHandler()));

		TLAlert alert = new TLAlert(expirationDetection, handler);
		alerts.add(alert);
		job.setTLAlerts(alerts);

		job.onlineRefresh();

		assertTrue(callback.called);
	}

	@Test
	void testOJLocationChangedCatchCalled() {
		CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
		trustedCertificateSource.addCertificate(lotlSigningCertificate);

		TLValidationJob job = new TLValidationJob();

		job.setTrustedListCertificateSource(new TrustedListsCertificateSource());
		job.setOnlineDataLoader(getOnlineDataLoader(LOTL, LOTL_URL));

		LOTLSource lotlSource = new LOTLSource();

		lotlSource.setPivotSupport(true);
		lotlSource.setUrl(LOTL_URL);
		lotlSource.setCertificateSource(trustedCertificateSource);

		lotlSource.setSigningCertificatesAnnouncementPredicate(
				new OfficialJournalSchemeInformationURI("https://eur-lex.europa.eu/legal-content/blabla"));

		job.setListOfTrustedListSources(lotlSource);

		List<Alert<LOTLInfo>> alerts = new ArrayList<>();
		OJUrlChangeDetection ojUrlDetection = new OJUrlChangeDetection(lotlSource);

		CallbackAlertHandler callback = new CallbackAlertHandler();
		AlertHandler<LOTLInfo> handler = new CompositeAlertHandler<LOTLInfo>(Arrays.asList(callback, new LogOJUrlChangeAlertHandler()));

		LOTLAlert alert = new LOTLAlert(ojUrlDetection, handler);
		alerts.add(alert);
		job.setLOTLAlerts(alerts);

		job.onlineRefresh();

		assertTrue(callback.called);
	}

	@Test
	void testLOTLLocationChangeDetection() {
		CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
		trustedCertificateSource.addCertificate(lotlSigningCertificate);

		TLValidationJob job = new TLValidationJob();

		job.setTrustedListCertificateSource(new TrustedListsCertificateSource());
		job.setOnlineDataLoader(getOnlineDataLoader(LOTL, OLD_LOTL_URL));

		LOTLSource lotlSource = new LOTLSource();

		lotlSource.setPivotSupport(true);
		lotlSource.setUrl(OLD_LOTL_URL);
		lotlSource.setCertificateSource(trustedCertificateSource);
		job.setListOfTrustedListSources(lotlSource);

		List<Alert<LOTLInfo>> alerts = new ArrayList<>();
		LOTLLocationChangeDetection lotlLocationDetection = new LOTLLocationChangeDetection(lotlSource);

		CallbackAlertHandler callback = new CallbackAlertHandler();
		AlertHandler<LOTLInfo> handler = new CompositeAlertHandler<LOTLInfo>(Arrays.asList(callback, new LogLOTLLocationChangeAlertHandler()));

		LOTLAlert alert = new LOTLAlert(lotlLocationDetection, handler);
		alerts.add(alert);
		job.setLOTLAlerts(alerts);

		job.onlineRefresh();

		assertTrue(callback.called);

	}

	private TLSource getTLSource(String url) {
		TLSource czTLSource = new TLSource();
		czTLSource.setUrl(url);
		CertificateSource certificateSource = new CommonCertificateSource();
		certificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
				"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"));
		czTLSource.setCertificateSource(certificateSource);
		return czTLSource;
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
