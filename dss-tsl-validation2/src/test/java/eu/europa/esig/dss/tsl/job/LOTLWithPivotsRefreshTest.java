package eu.europa.esig.dss.tsl.job;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.tsl.cache.state.CacheStateEnum;
import eu.europa.esig.dss.tsl.dto.DownloadCacheDTO;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.dto.ValidationCacheDTO;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.summary.LOTLInfo;
import eu.europa.esig.dss.tsl.summary.PivotInfo;
import eu.europa.esig.dss.tsl.summary.ValidationJobSummary;

public class LOTLWithPivotsRefreshTest {

	@TempDir
	File cacheDirectory;

	@Test
	public void test() {

		FileCacheDataLoader offlineFileLoader = getOfflineFileLoader(correctUrlMap());

		TLValidationJob job = new TLValidationJob();
		job.setListOfTrustedListSources(getLOTLSource());
		job.setOfflineDataLoader(offlineFileLoader);

		job.offlineRefresh();

		checks(job, Indication.TOTAL_PASSED);

		job.offlineRefresh();

		checks(job, Indication.TOTAL_PASSED);
	}

	@Test
	public void testMissingPivots() {

		FileCacheDataLoader offlineFileLoader = getOfflineFileLoader(missingUrlMap());

		TLValidationJob job = new TLValidationJob();
		job.setListOfTrustedListSources(getLOTLSource());
		job.setOfflineDataLoader(offlineFileLoader);

		job.offlineRefresh();

		ValidationJobSummary summary = job.getSummary();
		assertNotNull(summary);
		assertEquals(1, summary.getNumberOfProcessedLOTLs());
		List<LOTLInfo> lotlInfos = summary.getLOTLInfos();
		assertEquals(1, lotlInfos.size());
		LOTLInfo lotlInfo = lotlInfos.get(0);

		ValidationCacheDTO validationCacheInfo = lotlInfo.getValidationCacheInfo();
		assertEquals(Indication.INDETERMINATE, validationCacheInfo.getIndication());
	}

	@Test
	public void testMissingCert() {

		FileCacheDataLoader offlineFileLoader = getOfflineFileLoader(correctUrlMap());

		TLValidationJob job = new TLValidationJob();
		LOTLSource lotlSource = getLOTLSource();
		lotlSource.setCertificateSource(new CommonCertificateSource());
		job.setListOfTrustedListSources(lotlSource);
		job.setOfflineDataLoader(offlineFileLoader);

		job.offlineRefresh();

		checks(job, Indication.INDETERMINATE);

		job.offlineRefresh();

		checks(job, Indication.INDETERMINATE);
	}

	@Test
	public void testNoCertSource() {

		FileCacheDataLoader offlineFileLoader = getOfflineFileLoader(correctUrlMap());

		TLValidationJob job = new TLValidationJob();

		LOTLSource lotlSource = new LOTLSource();
		lotlSource.setUrl("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-247-mp.xml");
		lotlSource.setPivotSupport(true);
		job.setListOfTrustedListSources(lotlSource);
		job.setOfflineDataLoader(offlineFileLoader);

		job.offlineRefresh();

		ValidationJobSummary summary = job.getSummary();
		assertNotNull(summary);
		assertEquals(1, summary.getNumberOfProcessedLOTLs());
		List<LOTLInfo> lotlInfos = summary.getLOTLInfos();
		assertEquals(1, lotlInfos.size());
		LOTLInfo lotlInfo = lotlInfos.get(0);

		ValidationCacheDTO validationCacheInfo = lotlInfo.getValidationCacheInfo();
		assertEquals(CacheStateEnum.ERROR, validationCacheInfo.getCacheState());
		assertEquals("The certificate source is null", validationCacheInfo.getExceptionMessage());
		assertNotNull(validationCacheInfo.getExceptionStackTrace());
	}

	@Test
	public void testWrongCert() {

		FileCacheDataLoader offlineFileLoader = getOfflineFileLoader(correctUrlMap());

		TLValidationJob job = new TLValidationJob();
		LOTLSource lotlSource = getLOTLSource();
		CommonCertificateSource certificateSource = new CommonCertificateSource();
		certificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
				"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"));
		lotlSource.setCertificateSource(certificateSource);
		job.setListOfTrustedListSources(lotlSource);
		job.setOfflineDataLoader(offlineFileLoader);

		job.offlineRefresh();

		checks(job, Indication.INDETERMINATE);

		job.offlineRefresh();

		checks(job, Indication.INDETERMINATE);
	}

	private FileCacheDataLoader getOfflineFileLoader(Map<String, DSSDocument> urlMap) {
		FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader();
		offlineFileLoader.setCacheExpirationTime(Long.MAX_VALUE);
		offlineFileLoader.setDataLoader(new MockDataLoader(urlMap));
		offlineFileLoader.setFileCacheDirectory(cacheDirectory);
		return offlineFileLoader;
	}

	private Map<String, DSSDocument> correctUrlMap() {
		Map<String, DSSDocument> urlMap = new HashMap<String, DSSDocument>();
		urlMap.put("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-247-mp.xml",
				new FileDocument("src/test/resources/lotlCache/tl_pivot_247_mp.xml"));
		urlMap.put("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-226-mp.xml",
				new FileDocument("src/test/resources/lotlCache/tl_pivot_226_mp.xml"));
		urlMap.put("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-191-mp.xml",
				new FileDocument("src/test/resources/lotlCache/tl_pivot_191_mp.xml"));
		urlMap.put("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-172-mp.xml",
				new FileDocument("src/test/resources/lotlCache/tl_pivot_172_mp.xml"));
		return urlMap;
	}

	private Map<String, DSSDocument> missingUrlMap() {
		Map<String, DSSDocument> urlMap = new HashMap<String, DSSDocument>();
		urlMap.put("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-247-mp.xml",
				new FileDocument("src/test/resources/lotlCache/tl_pivot_247_mp.xml"));
		urlMap.put("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-226-mp.xml",
				null);
		urlMap.put("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-191-mp.xml",
				null);
		urlMap.put("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-172-mp.xml",
				new FileDocument("src/test/resources/lotlCache/tl_pivot_172_mp.xml"));
		return urlMap;
	}

	private void checks(TLValidationJob job, Indication expectedIndication) {
		ValidationJobSummary summary = job.getSummary();
		assertNotNull(summary);
		assertEquals(1, summary.getNumberOfProcessedLOTLs());
		List<LOTLInfo> lotlInfos = summary.getLOTLInfos();
		assertEquals(1, lotlInfos.size());
		LOTLInfo lotlInfo = lotlInfos.get(0);
		DownloadCacheDTO downloadCacheInfo = lotlInfo.getDownloadCacheInfo();
		assertNotNull(downloadCacheInfo);
		assertNotNull(downloadCacheInfo.getLastSuccessDate());
		assertEquals(CacheStateEnum.DESYNCHRONIZED, downloadCacheInfo.getCacheState());
		ParsingCacheDTO parsingCacheInfo = lotlInfo.getParsingCacheInfo();
		assertNotNull(parsingCacheInfo);
		assertEquals(CacheStateEnum.DESYNCHRONIZED, parsingCacheInfo.getCacheState());
		ValidationCacheDTO validationCacheInfo = lotlInfo.getValidationCacheInfo();
		assertNotNull(validationCacheInfo);
		assertEquals(CacheStateEnum.DESYNCHRONIZED, validationCacheInfo.getCacheState());

		// LOTL
		assertEquals(expectedIndication, validationCacheInfo.getIndication());
		assertNotNull(validationCacheInfo.getSigningCertificate());
		assertNotNull(validationCacheInfo.getSigningTime());

		List<PivotInfo> pivotInfos = lotlInfo.getPivotInfos();
		assertEquals(4, pivotInfos.size());

		for (PivotInfo pivotInfo : pivotInfos) {
			ValidationCacheDTO pivotValidationCacheInfo = pivotInfo.getValidationCacheInfo();
			assertEquals(CacheStateEnum.DESYNCHRONIZED, pivotValidationCacheInfo.getCacheState());
			assertEquals(expectedIndication, pivotValidationCacheInfo.getIndication());
			assertNotNull(pivotValidationCacheInfo.getSigningCertificate());
			assertNotNull(pivotValidationCacheInfo.getSigningTime());
		}
	}

	private LOTLSource getLOTLSource() {
		LOTLSource lotl = new LOTLSource();
		lotl.setUrl("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-247-mp.xml");
		lotl.setPivotSupport(true);
		CertificateSource certificateSource = new CommonCertificateSource();
		certificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
				"MIID/DCCAuSgAwIBAgIQEAAAAAAAWgS4SGkJJUcHdzANBgkqhkiG9w0BAQUFADAzMQswCQYDVQQGEwJCRTETMBEGA1UEAxMKQ2l0aXplbiBDQTEPMA0GA1UEBRMGMjAxMzA2MB4XDTEzMDcxNzE3NDQwOFoXDTE4MDcxMzIzNTk1OVowbjELMAkGA1UEBhMCQkUxITAfBgNVBAMTGFBpZXJyZSBEYW1hcyAoU2lnbmF0dXJlKTEOMAwGA1UEBBMFRGFtYXMxFjAUBgNVBCoMDVBpZXJyZSBBbmRyw6kxFDASBgNVBAUTCzYwMDIxMjExOTE5MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCMv+7DvhzLwG3prirUDGaYRS2+jBZtN2cYXuloKSqAc5Q58FEmk0gsZRF+/4dkt8hgCvbBcpmG6FcvTfNxQbxPX88yYwpBYsWnJ3aD5P4QrN2+fZxwxfXxRRcX+t30IBpr+WYFv/GhJhoFo0LWUehC4eyvnMfP4J/MR4TGlQRrcwIDAQABo4IBUzCCAU8wHwYDVR0jBBgwFoAUww/Dck0/3rI43jkuR2RQ//KP88cwbgYIKwYBBQUHAQEEYjBgMDYGCCsGAQUFBzAChipodHRwOi8vY2VydHMuZWlkLmJlbGdpdW0uYmUvYmVsZ2l1bXJzMi5jcnQwJgYIKwYBBQUHMAGGGmh0dHA6Ly9vY3NwLmVpZC5iZWxnaXVtLmJlMEQGA1UdIAQ9MDswOQYHYDgJAQECATAuMCwGCCsGAQUFBwIBFiBodHRwOi8vcmVwb3NpdG9yeS5laWQuYmVsZ2l1bS5iZTA5BgNVHR8EMjAwMC6gLKAqhihodHRwOi8vY3JsLmVpZC5iZWxnaXVtLmJlL2VpZGMyMDEzMDYuY3JsMA4GA1UdDwEB/wQEAwIGQDARBglghkgBhvhCAQEEBAMCBSAwGAYIKwYBBQUHAQMEDDAKMAgGBgQAjkYBATANBgkqhkiG9w0BAQUFAAOCAQEAEE3KGmLX5XXqArQwIZQmQEE6orKSu3a1z8ey1txsZC4rMk1vpvC6MtsfDaU4N6ooprhcM/WAlcIGOPCNhvxV+xcY7gUBwa6myiClnK0CMSiGYHqWcJG8ns13B9f0+5PJqsoziPoksXb2A9VXkr5aEdEmBYLjh7wG7GwAuDgDT0v87qtphN02/MAlJcNqT3JUUAotD7yfEybmK245jKo+pTYeCHGh7r1HzVWhbUDcQ/e1PpQXjVqBmr4k1ACtuu4H19t6K1P5kf7ta5JFEJPFgy3Hxt6YqzoY07WTVEpS4gJqtleIdX1Fhse7jq83ltcCzlfysBRqY/okUzipo1rbQw=="));
		lotl.setCertificateSource(certificateSource);
		return lotl;
	}

}
