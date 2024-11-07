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
package eu.europa.esig.dss.tsl.job;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.model.tsl.LOTLInfo;
import eu.europa.esig.dss.model.tsl.TLInfo;
import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.tsl.cache.CacheCleaner;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.sync.SynchronizationStrategy;

class LOTLChangesTest {

	// Diff LOTL 248 / 250
	// URL change for SI
	// Certs change for FR

	@TempDir
	File cacheDirectory;

	@Test
	void test() {
		FileCacheDataLoader offlineFileLoader = getOfflineFileLoader(originalFiles());

		TLValidationJob job = new TLValidationJob();
		job.setListOfTrustedListSources(getLOTLSource());
		job.setOfflineDataLoader(offlineFileLoader);
		TrustedListsCertificateSource trustedListCertificateSource = new TrustedListsCertificateSource();
		job.setTrustedListCertificateSource(trustedListCertificateSource);

		CacheCleaner cacheCleaner = new CacheCleaner();
		cacheCleaner.setCleanFileSystem(true);
		cacheCleaner.setCleanMemory(true);
		cacheCleaner.setDSSFileLoader(offlineFileLoader);
		job.setCacheCleaner(cacheCleaner);

		SynchronizationStrategy rejectAll = new SynchronizationStrategy() {

			@Override
			public boolean canBeSynchronized(LOTLInfo listOfTrustedList) {
				return false;
			}

			@Override
			public boolean canBeSynchronized(TLInfo trustedList) {
				return false;
			}
		};
		job.setSynchronizationStrategy(rejectAll);

//		job.setDebug(true);

		job.offlineRefresh();

		TLValidationJobSummary summary = job.getSummary();
		List<LOTLInfo> lotlInfos = summary.getLOTLInfos();
		assertEquals(1, lotlInfos.size());
		LOTLInfo lotlInfo = lotlInfos.get(0);
		List<TLInfo> tlInfos = lotlInfo.getTLInfos();
		assertEquals(31, tlInfos.size());

		TLInfo france = getFrance(tlInfos);
		assertNotNull(france);
		assertTrue(france.getValidationCacheInfo().isValid());
		Date firstSigningTime = france.getValidationCacheInfo().getSigningTime();
		Date firstIssueDate = france.getParsingCacheInfo().getIssueDate();

		job.setOnlineDataLoader(getOnlineFileLoader(refreshFiles()));

		job.onlineRefresh();

		summary = job.getSummary();
		lotlInfos = summary.getLOTLInfos();
		assertEquals(1, lotlInfos.size());
		lotlInfo = lotlInfos.get(0);

		tlInfos = lotlInfo.getTLInfos();
		assertEquals(31, tlInfos.size()); // same TLs number after cleaner

		france = getFrance(tlInfos);
		assertNotNull(france);

		assertTrue(france.getValidationCacheInfo().isValid());
		assertNotEquals(firstSigningTime, france.getValidationCacheInfo().getSigningTime());
		assertNotEquals(firstIssueDate, france.getParsingCacheInfo().getIssueDate());

		// validate rejectAll
		List<CertificateToken> certificates = trustedListCertificateSource.getCertificates();
		assertEquals(0, certificates.size());
	}

	private TLInfo getFrance(List<TLInfo> tlInfos) {
		for (TLInfo tlInfo : tlInfos) {
			if ("FR".equals(tlInfo.getParsingCacheInfo().getTerritory())) {
				return tlInfo;
			}
		}
		return null;
	}

	private FileCacheDataLoader getOfflineFileLoader(Map<String, DSSDocument> urlMap) {
		FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader();
		offlineFileLoader.setCacheExpirationTime(Long.MAX_VALUE);
		offlineFileLoader.setDataLoader(new MockDataLoader(urlMap));
		offlineFileLoader.setFileCacheDirectory(cacheDirectory);
		return offlineFileLoader;
	}

	private FileCacheDataLoader getOnlineFileLoader(Map<String, DSSDocument> urlMap) {
		FileCacheDataLoader onlineFileLoader = new FileCacheDataLoader();
		onlineFileLoader.setCacheExpirationTime(0);
		onlineFileLoader.setDataLoader(new MockDataLoader(urlMap));
		onlineFileLoader.setFileCacheDirectory(cacheDirectory);
		return onlineFileLoader;
	}

	private LOTLSource getLOTLSource() {
		LOTLSource lotl = new LOTLSource();
		lotl.setUrl("EU");
		CertificateSource certificateSource = new CommonCertificateSource();
		certificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
				"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"));
		lotl.setCertificateSource(certificateSource);
		return lotl;
	}

	private Map<String, DSSDocument> originalFiles() {
		DSSDocument lotl248 = new FileDocument("src/test/resources/eu-lotl.xml");

		Map<String, DSSDocument> urlMap = new HashMap<>();
		urlMap.put("EU", lotl248);

		String siURL248 = "http://www.mju.gov.si/fileadmin/mju.gov.si/pageuploads/DID/Informacijska_druzba/eIDAS/SI_TL.xml";
		DSSDocument siTL = new FileDocument("src/test/resources/lotlCache/SI.xml");

		urlMap.put(siURL248, siTL);

		String frURL = "http://www.ssi.gouv.fr/eidas/TL-FR.xml";
		DSSDocument frTL = new FileDocument("src/test/resources/lotlCache/FR.xml");

		urlMap.put(frURL, frTL);

		return urlMap;
	}

	private Map<String, DSSDocument> refreshFiles() {

		DSSDocument lotl250 = new FileDocument("src/test/resources/eu-lotl-250.xml");

		Map<String, DSSDocument> urlMap = new HashMap<>();
		urlMap.put("EU", lotl250);

		String siURL248 = "http://www.mju.gov.si/fileadmin/mju.gov.si/pageuploads/DID/Informacijska_druzba/eIDAS/SI_TL.xml";
		DSSDocument siTL = new FileDocument("src/test/resources/lotlCache/SI.xml");

		urlMap.put(siURL248, siTL);

		String frURL = "http://www.ssi.gouv.fr/eidas/TL-FR.xml";
		DSSDocument frTL = new FileDocument("src/test/resources/lotlCache/FR_59.xml");

		urlMap.put(frURL, frTL);

		return urlMap;
	}

}
