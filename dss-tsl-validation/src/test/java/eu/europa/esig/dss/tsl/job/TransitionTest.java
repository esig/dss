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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.tsl.InfoRecord;
import eu.europa.esig.dss.model.tsl.TLInfo;
import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.tsl.cache.state.CacheStateEnum;
import eu.europa.esig.dss.tsl.source.TLSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TransitionTest {

	@TempDir
	File cacheDirectory;

	private static final DSSDocument CZ = new FileDocument("src/test/resources/lotlCache/CZ.xml");
	private static final DSSDocument CZ_NULL = null;
	private static final DSSDocument CZ_NO_XML = new FileDocument("src/test/resources/lotlCache/CZ.pdf");
	private static final DSSDocument CZ_BROKEN_SIG = new FileDocument("src/test/resources/lotlCache/CZ_broken-sig.xml");
	private static final DSSDocument CZ_NO_SIG = new FileDocument("src/test/resources/lotlCache/CZ_no-sig.xml");
	private static final DSSDocument CZ_NOT_CONFORM = new FileDocument("src/test/resources/lotlCache/CZ_not-conform.xml");
	private static final DSSDocument CZ_NOT_COMPLIANT = new FileDocument("src/test/resources/lotlCache/CZ_not-compliant.xml");
	private static final DSSDocument CZ_NOT_PARSABLE = new FileDocument("src/test/resources/lotlCache/eu-lotl_not-parsable.xml");

	@Test
	void nullDoc() {

		String url = "null-doc";

		TLValidationJob job = new TLValidationJob();
		job.setTrustedListSources(getTLSource(url));
		job.setOnlineDataLoader(getOnlineDataLoader(CZ_NULL, url));

		job.onlineRefresh();

		TLValidationJobSummary firstSummary = job.getSummary();
		TLInfo firstCZ = firstSummary.getOtherTLInfos().get(0);
		assertNull(firstCZ.getDownloadCacheInfo().getLastSuccessSynchronizationTime());
		checkSummary(firstSummary, CacheStateEnum.ERROR, CacheStateEnum.REFRESH_NEEDED, CacheStateEnum.REFRESH_NEEDED);

		// Wait
		Calendar nextMilliSecond = Calendar.getInstance();
		nextMilliSecond.add(Calendar.MILLISECOND, 1);
		await().atMost(1, TimeUnit.SECONDS).until(() -> Calendar.getInstance().getTime().compareTo(nextMilliSecond.getTime()) > 0);

		job.onlineRefresh();

		TLValidationJobSummary secondSummary = job.getSummary();
		TLInfo secondCZ = secondSummary.getOtherTLInfos().get(0);
		assertNull(secondCZ.getDownloadCacheInfo().getLastSuccessSynchronizationTime());
		checkSummary(secondSummary, CacheStateEnum.ERROR, CacheStateEnum.REFRESH_NEEDED, CacheStateEnum.REFRESH_NEEDED);

		// Keep the first error time
		assertEquals(firstCZ.getDownloadCacheInfo().getExceptionFirstOccurrenceTime(), secondCZ.getDownloadCacheInfo().getExceptionFirstOccurrenceTime());
		assertEquals(firstCZ.getDownloadCacheInfo().getExceptionMessage(), secondCZ.getDownloadCacheInfo().getExceptionMessage());
	}

	@Test
	void nullDocNullCertSource() {

		String url = "null-doc";

		TLValidationJob job = new TLValidationJob();
		TLSource tlSource = new TLSource();
		tlSource.setUrl(url);
		job.setTrustedListSources(tlSource);
		job.setOnlineDataLoader(getOnlineDataLoader(CZ_NULL, url));

		job.onlineRefresh();

		checkSummary(job.getSummary(), CacheStateEnum.ERROR, CacheStateEnum.REFRESH_NEEDED, CacheStateEnum.REFRESH_NEEDED);

		job.onlineRefresh();

		checkSummary(job.getSummary(), CacheStateEnum.ERROR, CacheStateEnum.REFRESH_NEEDED, CacheStateEnum.REFRESH_NEEDED);
	}

	@Test
	void nullToValidDoc() {

		String url = "null-to-valid-doc";

		TLValidationJob job = new TLValidationJob();
		job.setTrustedListCertificateSource(new TrustedListsCertificateSource());
		job.setTrustedListSources(getTLSource(url));

		job.setOnlineDataLoader(getOnlineDataLoader(CZ_NULL, url));
		job.onlineRefresh();
		checkSummary(job.getSummary(), CacheStateEnum.ERROR, CacheStateEnum.REFRESH_NEEDED, CacheStateEnum.REFRESH_NEEDED);

		job.setOnlineDataLoader(getOnlineDataLoader(CZ, url));
		job.onlineRefresh();
		TLValidationJobSummary summarySuccess = job.getSummary();
		checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);

		job.setOnlineDataLoader(getOnlineDataLoader(CZ_NULL, url));
		job.onlineRefresh();
		TLValidationJobSummary summaryFail = job.getSummary();
		checkSummary(summaryFail, CacheStateEnum.ERROR, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);

		TLInfo successTlInfo = summarySuccess.getOtherTLInfos().get(0);
		TLInfo failTlInfo = summaryFail.getOtherTLInfos().get(0);

		assertEquals(successTlInfo.getDownloadCacheInfo().getLastStateTransitionTime(), failTlInfo.getDownloadCacheInfo().getLastStateTransitionTime());
		assertEquals(successTlInfo.getDownloadCacheInfo().getLastSuccessSynchronizationTime(), failTlInfo.getDownloadCacheInfo().getLastSuccessSynchronizationTime());
		assertNotEquals(successTlInfo.getDownloadCacheInfo().getExceptionMessage(), failTlInfo.getDownloadCacheInfo().getExceptionMessage());

		assertEquals(successTlInfo.getParsingCacheInfo().getLastStateTransitionTime(), failTlInfo.getParsingCacheInfo().getLastStateTransitionTime());
		assertEquals(successTlInfo.getValidationCacheInfo().getLastStateTransitionTime(), failTlInfo.getValidationCacheInfo().getLastStateTransitionTime());

	}
	
	@Test
	void lastDownloadAttempTest() {
		String url = "null-to-valid-doc";

		TLValidationJob job = new TLValidationJob();
		job.setTrustedListCertificateSource(new TrustedListsCertificateSource());
		job.setTrustedListSources(getTLSource(url));
		
		job.setOnlineDataLoader(getOnlineDataLoader(CZ_NULL, url));
		job.onlineRefresh();
		checkSummary(job.getSummary(), CacheStateEnum.ERROR, CacheStateEnum.REFRESH_NEEDED, CacheStateEnum.REFRESH_NEEDED);
		
		TLValidationJobSummary summary = job.getSummary();
		TLInfo tlInfo = summary.getOtherTLInfos().get(0);
		
		assertNull(tlInfo.getDownloadCacheInfo().getLastSuccessSynchronizationTime());
		assertNotNull(tlInfo.getDownloadCacheInfo().getLastStateTransitionTime());
		assertNotNull(tlInfo.getDownloadCacheInfo().getExceptionLastOccurrenceTime());
		assertEquals(tlInfo.getDownloadCacheInfo().getExceptionLastOccurrenceTime(), tlInfo.getDownloadCacheInfo().getLastDownloadAttemptTime());
		
		job.setOnlineDataLoader(getOnlineDataLoader(CZ, url));
		job.onlineRefresh();
		checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);
		summary = job.getSummary();
		tlInfo = summary.getOtherTLInfos().get(0);
		
		assertNull(tlInfo.getDownloadCacheInfo().getExceptionLastOccurrenceTime());
		assertNotNull(tlInfo.getDownloadCacheInfo().getLastStateTransitionTime());
		assertNotNull(tlInfo.getDownloadCacheInfo().getLastSuccessSynchronizationTime());
		assertEquals(tlInfo.getDownloadCacheInfo().getLastStateTransitionTime(), tlInfo.getDownloadCacheInfo().getLastDownloadAttemptTime());

		job.setOnlineDataLoader(getOnlineDataLoader(CZ_NULL, url));
		job.onlineRefresh();
		checkSummary(job.getSummary(), CacheStateEnum.ERROR, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);
		summary = job.getSummary();
		tlInfo = summary.getOtherTLInfos().get(0);

		assertNotNull(tlInfo.getDownloadCacheInfo().getLastSuccessSynchronizationTime());
		assertNotNull(tlInfo.getDownloadCacheInfo().getLastStateTransitionTime());
		assertNotNull(tlInfo.getDownloadCacheInfo().getExceptionLastOccurrenceTime());
		assertEquals(tlInfo.getDownloadCacheInfo().getExceptionLastOccurrenceTime(), tlInfo.getDownloadCacheInfo().getLastDownloadAttemptTime());

	}

	@Test
	void validToNulldDoc() {

		String url = "valid-to-null-doc";

		TLValidationJob job = new TLValidationJob();
		job.setTrustedListCertificateSource(new TrustedListsCertificateSource());
		job.setTrustedListSources(getTLSource(url));

		job.setOnlineDataLoader(getOnlineDataLoader(CZ, url));
		job.onlineRefresh();
		checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);

		job.setOnlineDataLoader(getOnlineDataLoader(CZ_NULL, url));
		job.onlineRefresh();
		// valid parsing and signature are still present
		checkSummary(job.getSummary(), CacheStateEnum.ERROR, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);

		job.setOnlineDataLoader(getOnlineDataLoader(CZ, url));
		job.onlineRefresh();
		checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);
	}

	@Test
	void validToNonCompliantDoc() {

		String url = "valid-to-null-doc";

		TLValidationJob job = new TLValidationJob();
		job.setTrustedListCertificateSource(new TrustedListsCertificateSource());
		job.setTrustedListSources(getTLSource(url));

		job.setOnlineDataLoader(getOnlineDataLoader(CZ, url));
		job.onlineRefresh();
		checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);

		job.setOnlineDataLoader(getOnlineDataLoader(CZ_NOT_COMPLIANT, url));
		job.onlineRefresh();
		checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);

		job.setOnlineDataLoader(getOnlineDataLoader(CZ, url));
		job.onlineRefresh();
		checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);
	}

	@Test
	void validToNotConform() {

		String url = "valid-to-null-doc";

		TLValidationJob job = new TLValidationJob();
		job.setTrustedListCertificateSource(new TrustedListsCertificateSource());
		job.setTrustedListSources(getTLSource(url));

		job.setOnlineDataLoader(getOnlineDataLoader(CZ, url));
		job.onlineRefresh();
		checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);

		job.setOnlineDataLoader(getOnlineDataLoader(CZ_NOT_CONFORM, url));
		job.onlineRefresh();
		// Change not detected
		checkSummary(job.getSummary(), CacheStateEnum.ERROR, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);

		job.setOnlineDataLoader(getOnlineDataLoader(CZ, url));
		job.onlineRefresh();
		checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);
	}

	@Test
	void validToNonParsableDoc() {

		String url = "valid-to-null-doc";

		TLValidationJob job = new TLValidationJob();
		job.setTrustedListCertificateSource(new TrustedListsCertificateSource());
		job.setTrustedListSources(getTLSource(url));

		job.setOnlineDataLoader(getOnlineDataLoader(CZ, url));
		job.onlineRefresh();
		checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);

		job.setOnlineDataLoader(getOnlineDataLoader(CZ_NOT_PARSABLE, url));
		job.onlineRefresh();
		checkSummary(job.getSummary(), CacheStateEnum.ERROR, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);

		job.setOnlineDataLoader(getOnlineDataLoader(CZ, url));
		job.onlineRefresh();
		checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);
	}

	@Test
	void nullToNonCompliantAndThenValidDoc() {

		String url = "null-to-valid-doc";

		TLValidationJob job = new TLValidationJob();
		job.setTrustedListCertificateSource(new TrustedListsCertificateSource());
		job.setTrustedListSources(getTLSource(url));

		job.setOnlineDataLoader(getOnlineDataLoader(CZ_NULL, url));
		job.onlineRefresh();
		checkSummary(job.getSummary(), CacheStateEnum.ERROR, CacheStateEnum.REFRESH_NEEDED, CacheStateEnum.REFRESH_NEEDED);

		job.setOnlineDataLoader(getOnlineDataLoader(CZ_NOT_COMPLIANT, url));
		job.onlineRefresh();
		checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);

		job.setOnlineDataLoader(getOnlineDataLoader(CZ, url));
		job.onlineRefresh();
		checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);
	}

	@Test
	void noXml() {

		String url = "no-xml";

		TLValidationJob job = new TLValidationJob();
		job.setTrustedListSources(getTLSource(url));
		job.setOnlineDataLoader(getOnlineDataLoader(CZ_NO_XML, url));

		job.onlineRefresh();

		checkSummary(job.getSummary(), CacheStateEnum.ERROR, CacheStateEnum.REFRESH_NEEDED, CacheStateEnum.REFRESH_NEEDED);
	}

	@Test
	void notConform() {

		String url = "no-conform";

		TLValidationJob job = new TLValidationJob();
		job.setTrustedListSources(getTLSource(url));
		job.setOnlineDataLoader(getOnlineDataLoader(CZ_NOT_CONFORM, url));

		job.onlineRefresh();

		checkSummary(job.getSummary(), CacheStateEnum.ERROR, CacheStateEnum.REFRESH_NEEDED, CacheStateEnum.REFRESH_NEEDED);
	}

	@Test
	void notCompliant() {

		String url = "no-compliant";

		TLValidationJob job = new TLValidationJob();
		job.setTrustedListSources(getTLSource(url));
		job.setOnlineDataLoader(getOnlineDataLoader(CZ_NOT_COMPLIANT, url));

		job.onlineRefresh();

		checkSummary(job.getSummary(), CacheStateEnum.DESYNCHRONIZED, CacheStateEnum.DESYNCHRONIZED, CacheStateEnum.DESYNCHRONIZED);
	}

	@Test
	void validDoc() {

		String url = "valid-doc";

		TLValidationJob job = new TLValidationJob();
		job.setTrustedListSources(getTLSource(url));
		job.setOnlineDataLoader(getOnlineDataLoader(CZ, url));

		job.onlineRefresh();

		checkSummary(job.getSummary(), CacheStateEnum.DESYNCHRONIZED, CacheStateEnum.DESYNCHRONIZED, CacheStateEnum.DESYNCHRONIZED);
	}

	@Test
	void noSig() {

		String url = "no-sig";

		TLValidationJob job = new TLValidationJob();
		job.setTrustedListSources(getTLSource(url));
		job.setOnlineDataLoader(getOnlineDataLoader(CZ_NO_SIG, url));

		job.onlineRefresh();

		checkSummary(job.getSummary(), CacheStateEnum.DESYNCHRONIZED, CacheStateEnum.DESYNCHRONIZED, CacheStateEnum.ERROR);
	}

	@Test
	void brokenSig() {

		String url = "broken-sig";

		TLValidationJob job = new TLValidationJob();
		job.setTrustedListSources(getTLSource(url));
		job.setOnlineDataLoader(getOnlineDataLoader(CZ_BROKEN_SIG, url));

		job.onlineRefresh();

		checkSummary(job.getSummary(), CacheStateEnum.DESYNCHRONIZED, CacheStateEnum.DESYNCHRONIZED, CacheStateEnum.DESYNCHRONIZED);
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

	private void checkSummary(TLValidationJobSummary summary, CacheStateEnum download, CacheStateEnum parsing, CacheStateEnum validation) {
		assertNotNull(summary);
		List<TLInfo> tlInfos = summary.getOtherTLInfos();
		assertEquals(1, tlInfos.size());
		assertEquals(1, summary.getNumberOfProcessedTLs());
		TLInfo tlInfo = tlInfos.get(0);
		
		checkCacheStateEnum(download, tlInfo.getDownloadCacheInfo());
		checkCacheStateEnum(parsing, tlInfo.getParsingCacheInfo());
		checkCacheStateEnum(validation, tlInfo.getValidationCacheInfo());
	}
	
	private void checkCacheStateEnum(CacheStateEnum cacheState, InfoRecord cacheInfo) {
		switch (cacheState) {
			case REFRESH_NEEDED:
				assertTrue(cacheInfo.isRefreshNeeded());
				assertFalse(cacheInfo.isDesynchronized());
				assertFalse(cacheInfo.isSynchronized());
				assertFalse(cacheInfo.isError());
				assertFalse(cacheInfo.isToBeDeleted());
				break;
			case DESYNCHRONIZED:
				assertFalse(cacheInfo.isRefreshNeeded());
				assertTrue(cacheInfo.isDesynchronized());
				assertFalse(cacheInfo.isSynchronized());
				assertFalse(cacheInfo.isError());
				assertFalse(cacheInfo.isToBeDeleted());
				break;
			case SYNCHRONIZED:
				assertFalse(cacheInfo.isRefreshNeeded());
				assertFalse(cacheInfo.isDesynchronized());
				assertTrue(cacheInfo.isSynchronized());
				assertFalse(cacheInfo.isError());
				assertFalse(cacheInfo.isToBeDeleted());
				break;
			case ERROR:
				assertFalse(cacheInfo.isRefreshNeeded());
				assertFalse(cacheInfo.isDesynchronized());
				assertFalse(cacheInfo.isSynchronized());
				assertTrue(cacheInfo.isError());
				assertFalse(cacheInfo.isToBeDeleted());
				break;
			case TO_BE_DELETED:
				assertFalse(cacheInfo.isRefreshNeeded());
				assertFalse(cacheInfo.isDesynchronized());
				assertFalse(cacheInfo.isSynchronized());
				assertFalse(cacheInfo.isError());
				assertTrue(cacheInfo.isToBeDeleted());
				break;
			default:
				throw new DSSException("Illegal state.");
		}
	}

}
