package eu.europa.esig.dss.tsl.job;

import static java.time.Duration.ofMillis;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeout;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.tsl.CertificatePivotStatus;
import eu.europa.esig.dss.spi.tsl.ConditionForQualifiers;
import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.PivotInfo;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.spi.tsl.TrustService;
import eu.europa.esig.dss.spi.tsl.TrustServiceProvider;
import eu.europa.esig.dss.spi.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.util.TimeDependentValues;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.cache.CacheCleaner;
import eu.europa.esig.dss.tsl.dto.condition.CompositeCondition;
import eu.europa.esig.dss.tsl.function.TrustServicePredicate;
import eu.europa.esig.dss.tsl.function.TrustServiceProviderPredicate;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;

public class TLValidationJobTest {

	private static TLValidationJob tlValidationJob;
	private static CacheCleaner cacheCleaner;
	private static FileCacheDataLoader offlineFileLoader;
	private static FileCacheDataLoader onlineFileLoader;
	
	private static Map<String, DSSDocument> urlMap;
	
	private static File cacheDirectory;
	
	private static final String LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";
	private LOTLSource lotlSource;
	private static CertificateToken lotlSigningCertificate;
	
	private static CertificateToken pivotSigningCertificate;
	
	private static final String CZ_URL = "https://tsl.gov.cz/publ/TSL_CZ.xtsl";
	private TLSource czSource;
	private static CertificateToken czSigningCertificate;
	
	@BeforeAll
	public static void initBeforeAll() throws IOException {
		urlMap = new HashMap<String, DSSDocument>();
		
		cacheDirectory = new File("target/cache");
		
		offlineFileLoader = new FileCacheDataLoader();
		offlineFileLoader.setCacheExpirationTime(Long.MAX_VALUE);
		offlineFileLoader.setDataLoader(new MockDataLoader(urlMap));
		offlineFileLoader.setFileCacheDirectory(cacheDirectory);
		
		Map<String, DSSDocument> onlineMap = new HashMap<String, DSSDocument>();
		onlineMap.putAll(urlMap);
		
		onlineFileLoader = new FileCacheDataLoader();
		onlineFileLoader.setCacheExpirationTime(0);
		onlineFileLoader.setDataLoader(new MockDataLoader(onlineMap));
		onlineFileLoader.setFileCacheDirectory(cacheDirectory);
		
		cacheCleaner = new CacheCleaner();
		cacheCleaner.setDSSFileLoader(offlineFileLoader);
		cacheCleaner.setCleanFileSystem(true);
		
		lotlSigningCertificate = DSSUtils.loadCertificateFromBase64EncodedString("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");
		pivotSigningCertificate = DSSUtils.loadCertificateFromBase64EncodedString("MIID/DCCAuSgAwIBAgIQEAAAAAAAWgS4SGkJJUcHdzANBgkqhkiG9w0BAQUFADAzMQswCQYDVQQGEwJCRTETMBEGA1UEAxMKQ2l0aXplbiBDQTEPMA0GA1UEBRMGMjAxMzA2MB4XDTEzMDcxNzE3NDQwOFoXDTE4MDcxMzIzNTk1OVowbjELMAkGA1UEBhMCQkUxITAfBgNVBAMTGFBpZXJyZSBEYW1hcyAoU2lnbmF0dXJlKTEOMAwGA1UEBBMFRGFtYXMxFjAUBgNVBCoMDVBpZXJyZSBBbmRyw6kxFDASBgNVBAUTCzYwMDIxMjExOTE5MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCMv+7DvhzLwG3prirUDGaYRS2+jBZtN2cYXuloKSqAc5Q58FEmk0gsZRF+/4dkt8hgCvbBcpmG6FcvTfNxQbxPX88yYwpBYsWnJ3aD5P4QrN2+fZxwxfXxRRcX+t30IBpr+WYFv/GhJhoFo0LWUehC4eyvnMfP4J/MR4TGlQRrcwIDAQABo4IBUzCCAU8wHwYDVR0jBBgwFoAUww/Dck0/3rI43jkuR2RQ//KP88cwbgYIKwYBBQUHAQEEYjBgMDYGCCsGAQUFBzAChipodHRwOi8vY2VydHMuZWlkLmJlbGdpdW0uYmUvYmVsZ2l1bXJzMi5jcnQwJgYIKwYBBQUHMAGGGmh0dHA6Ly9vY3NwLmVpZC5iZWxnaXVtLmJlMEQGA1UdIAQ9MDswOQYHYDgJAQECATAuMCwGCCsGAQUFBwIBFiBodHRwOi8vcmVwb3NpdG9yeS5laWQuYmVsZ2l1bS5iZTA5BgNVHR8EMjAwMC6gLKAqhihodHRwOi8vY3JsLmVpZC5iZWxnaXVtLmJlL2VpZGMyMDEzMDYuY3JsMA4GA1UdDwEB/wQEAwIGQDARBglghkgBhvhCAQEEBAMCBSAwGAYIKwYBBQUHAQMEDDAKMAgGBgQAjkYBATANBgkqhkiG9w0BAQUFAAOCAQEAEE3KGmLX5XXqArQwIZQmQEE6orKSu3a1z8ey1txsZC4rMk1vpvC6MtsfDaU4N6ooprhcM/WAlcIGOPCNhvxV+xcY7gUBwa6myiClnK0CMSiGYHqWcJG8ns13B9f0+5PJqsoziPoksXb2A9VXkr5aEdEmBYLjh7wG7GwAuDgDT0v87qtphN02/MAlJcNqT3JUUAotD7yfEybmK245jKo+pTYeCHGh7r1HzVWhbUDcQ/e1PpQXjVqBmr4k1ACtuu4H19t6K1P5kf7ta5JFEJPFgy3Hxt6YqzoY07WTVEpS4gJqtleIdX1Fhse7jq83ltcCzlfysBRqY/okUzipo1rbQw==");
		czSigningCertificate = DSSUtils.loadCertificateFromBase64EncodedString("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");
		
	}
	
	@BeforeEach
	public void init() {
		populateMap();
		
		czSource = new TLSource();
		czSource.setUrl(CZ_URL);
		CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
		trustedCertificateSource.addCertificate(czSigningCertificate);
		czSource.setCertificateSource(trustedCertificateSource);
		czSource.setTrustServicePredicate(new TrustServicePredicate() {
			@Override
			public boolean test(TSPServiceType t) {
				return true;
			}
		});
		czSource.setTrustServiceProviderPredicate(new TrustServiceProviderPredicate() {
			@Override
			public boolean test(TSPType t) {
				return true;
			}
		});
		

		lotlSource = new LOTLSource();
		lotlSource.setUrl(LOTL_URL);
		trustedCertificateSource = new CommonTrustedCertificateSource();
		trustedCertificateSource.addCertificate(lotlSigningCertificate);
		lotlSource.setCertificateSource(trustedCertificateSource);
		lotlSource.setPivotSupport(true);
	}
	
	private void populateMap() {
		urlMap.put(LOTL_URL, new FileDocument("src/test/resources/lotlCache/eu-lotl_original.xml"));
		
		urlMap.put("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-247-mp.xml", 
				new FileDocument("src/test/resources/lotlCache/tl_pivot_247_mp.xml"));
		urlMap.put("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-226-mp.xml", 
				new FileDocument("src/test/resources/lotlCache/tl_pivot_226_mp.xml"));
		urlMap.put("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-191-mp.xml", 
				new FileDocument("src/test/resources/lotlCache/tl_pivot_191_mp.xml"));
		urlMap.put("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-172-mp.xml", 
				new FileDocument("src/test/resources/lotlCache/tl_pivot_172_mp.xml"));
		
		urlMap.put("https://www.signatur.rtr.at/currenttl.xml", new FileDocument("src/test/resources/lotlCache/AT.xml"));
		urlMap.put("https://tsl.belgium.be/tsl-be.xml", new FileDocument("src/test/resources/lotlCache/BE.xml"));
		urlMap.put("https://crc.bg/files/_en/TSL_BG.xml", new FileDocument("src/test/resources/lotlCache/BG.xml"));
		urlMap.put("http://www.mcw.gov.cy/mcw/dec/dec.nsf/all/B28C11BBFDBAC045C2257E0D002937E9/$file/TSL-CY-sign.xml",
				new FileDocument("src/test/resources/lotlCache/CY.xml"));
		urlMap.put(CZ_URL, new FileDocument("src/test/resources/lotlCache/CZ.xml"));
		urlMap.put("https://www.nrca-ds.de/st/TSL-XML.xml", new FileDocument("src/test/resources/lotlCache/DE.xml"));
		urlMap.put("https://www.digst.dk/TSLDKxml", new FileDocument("src/test/resources/lotlCache/DK.xml"));
		urlMap.put("https://sr.riik.ee/tsl/estonian-tsl.xml", new FileDocument("src/test/resources/lotlCache/ES.xml")); // wrong country code
		urlMap.put("https://www.eett.gr/tsl/EL-TSL.xml", new FileDocument("src/test/resources/lotlCache/EL.xml"));
		urlMap.put("https://sede.minetur.gob.es/Prestadores/TSL/TSL.xml", new FileDocument("src/test/resources/lotlCache/ES.xml"));
		urlMap.put("https://dp.trustedlist.fi/fi-tl.xml", new FileDocument("src/test/resources/lotlCache/FI.xml"));
		urlMap.put("http://www.ssi.gouv.fr/eidas/TL-FR.xml", new FileDocument("src/test/resources/lotlCache/FR.xml"));
		urlMap.put("https://www.mingo.hr/TLS/TSL-HR.xml", new FileDocument("src/test/resources/lotlCache/HR.xml"));
		urlMap.put("http://www.nmhh.hu/tl/pub/HU_TL.xml", new FileDocument("src/test/resources/lotlCache/HU.xml"));
		urlMap.put("http://files.dcenr.gov.ie/rh/Irelandtslsigned.xml", new FileDocument("src/test/resources/lotlCache/IE.xml"));
		urlMap.put("http://www.neytendastofa.is/library/Files/TSl/tsl.xml", new FileDocument("src/test/resources/lotlCache/IS.xml"));
		urlMap.put("https://eidas.agid.gov.it/TL/TSL-IT.xml", new FileDocument("src/test/resources/lotlCache/IT.xml"));
		urlMap.put("https://www.llv.li/files/ak/xml-llv-ak-tsl.xml", new FileDocument("src/test/resources/lotlCache/LI.xml"));
		urlMap.put("https://elektroninisparasas.lt/LT-TSL.xml", new FileDocument("src/test/resources/lotlCache/LT.xml"));
		urlMap.put("https://portail-qualite.public.lu/content/dam/qualite/fr/publications/confiance-numerique/liste-confiance-nationale/tsl-xml/tsl.xml",
				new FileDocument("src/test/resources/lotlCache/LU.xml"));
		urlMap.put("https://trustlist.gov.lv/tsl/latvian-tsl.xml", new FileDocument("src/test/resources/lotlCache/LV.xml"));
		urlMap.put("https://www.mca.org.mt/tsl/MT_TSL.xml", new FileDocument("src/test/resources/lotlCache/MT.xml"));
		urlMap.put(
				"https://www.agentschaptelecom.nl/binaries/agentschap-telecom/documenten/publicaties/2018/januari/01/digitale-statuslijst-van-vertrouwensdiensten/current-tsl.xml",
				new FileDocument("src/test/resources/lotlCache/NL.xml"));
		urlMap.put("https://tl-norway.no/TSL/NO_TSL.XML", new FileDocument("src/test/resources/lotlCache/NO.xml"));
		urlMap.put("https://www.nccert.pl/tsl/PL_TSL.xml", new FileDocument("src/test/resources/lotlCache/PL.xml"));
		urlMap.put("https://www.gns.gov.pt/media/1894/TSLPT.xml", new FileDocument("src/test/resources/lotlCache/PT.xml"));
		// RO is missed
		urlMap.put("https://trustedlist.pts.se/SE-TL.xml", new FileDocument("src/test/resources/lotlCache/SE.xml"));
		urlMap.put("http://www.mju.gov.si/fileadmin/mju.gov.si/pageuploads/DID/Informacijska_druzba/eIDAS/SI_TL.xml",
				new FileDocument("src/test/resources/lotlCache/SI.xml"));
		urlMap.put("http://tl.nbu.gov.sk/kca/tsl/tsl.xml", new FileDocument("src/test/resources/lotlCache/SK.xml"));
		urlMap.put("https://www.tscheme.org/UK_TSL/TSL-UKsigned.xml", new FileDocument("src/test/resources/lotlCache/UK.xml"));
		urlMap.put("https://www.tscheme.org/UK_TSL/TSL-UKsigned.xml", new FileDocument("src/test/resources/lotlCache/UK.xml"));
		
		// Dummy Peruvian TL and good-user signed LOTL for testing
		urlMap.put("http://dss.nowina.lu/peru-lotl", new FileDocument("src/test/resources/peru-lotl.xml"));
		urlMap.put("https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml", new FileDocument("src/test/resources/tsl-pe.xml"));
	}
	
	@Test
	public void test() {
		updateTLUrl("src/test/resources/lotlCache/CZ.xml");

		TLValidationJob validationJob = getTLValidationJob();
		TLValidationJobSummary summary = validationJob.getSummary();
		
		assertEquals(0, summary.getNumberOfProcessedLOTLs());
		assertEquals(1, summary.getNumberOfProcessedTLs());
		
		List<TLInfo> tlInfos = summary.getOtherTLInfos();
		assertEquals(1, tlInfos.size());
		
		TLInfo czTL = tlInfos.get(0);
		assertNotNull(czTL.getDownloadCacheInfo().getLastLoadingDate());
		assertFalse(czTL.getDownloadCacheInfo().getLastSynchronizationDate().after(czTL.getDownloadCacheInfo().getLastLoadingDate()));
		
		assertTrue(czTL.getDownloadCacheInfo().isSynchronized());
		assertTrue(czTL.getParsingCacheInfo().isSynchronized());
		assertTrue(czTL.getValidationCacheInfo().isSynchronized());
		
		assertNull(czTL.getDownloadCacheInfo().getExceptionMessage());
		assertNull(czTL.getDownloadCacheInfo().getExceptionStackTrace());
		assertNull(czTL.getParsingCacheInfo().getExceptionMessage());
		assertNull(czTL.getParsingCacheInfo().getExceptionStackTrace());
		assertNull(czTL.getValidationCacheInfo().getExceptionMessage());
		assertNull(czTL.getValidationCacheInfo().getExceptionStackTrace());
		
		assertNotNull(czTL.getUrl());
		
		assertNotNull(czTL.getParsingCacheInfo().getSequenceNumber());
		assertNotNull(czTL.getParsingCacheInfo().getVersion());
		assertEquals("CZ", czTL.getParsingCacheInfo().getTerritory());
		assertNotNull(czTL.getParsingCacheInfo().getIssueDate());
		assertNotNull(czTL.getParsingCacheInfo().getNextUpdateDate());
		assertTrue(czTL.getParsingCacheInfo().getIssueDate().before(czTL.getParsingCacheInfo().getNextUpdateDate()));
		assertNotNull(czTL.getParsingCacheInfo().getDistributionPoints());
		assertThrows(UnsupportedOperationException.class, () -> czTL.getParsingCacheInfo().getDistributionPoints().add(new String()));
		assertNotNull(czTL.getParsingCacheInfo().getTrustServiceProviders());
		assertEquals(6, czTL.getParsingCacheInfo().getTrustServiceProviders().size());
		assertThrows(UnsupportedOperationException.class, () -> czTL.getParsingCacheInfo().getTrustServiceProviders().add(new TrustServiceProvider()));
		assertEquals(6, czTL.getParsingCacheInfo().getTrustServiceProviders().size());
		
		TrustServiceProvider trustServiceProvider = czTL.getParsingCacheInfo().getTrustServiceProviders().get(0);
		assertThrows(UnsupportedOperationException.class, () -> trustServiceProvider.getElectronicAddresses().put(new String(), new ArrayList<String>()));
		assertThrows(UnsupportedOperationException.class, () -> trustServiceProvider.getNames().put(new String(), new ArrayList<String>()));
		assertThrows(UnsupportedOperationException.class, () -> trustServiceProvider.getTradeNames().put(new String(), new ArrayList<String>()));
		assertThrows(UnsupportedOperationException.class, () -> trustServiceProvider.getInformation().put(new String(), new String()));
		assertThrows(UnsupportedOperationException.class, () -> trustServiceProvider.getPostalAddresses().put(new String(), new String()));
		assertThrows(UnsupportedOperationException.class, () -> trustServiceProvider.getRegistrationIdentifiers().add(new String()));
		assertThrows(UnsupportedOperationException.class, () -> trustServiceProvider.getServices().add(trustServiceProvider.getServices().get(0)));
		
		TrustService trustService = trustServiceProvider.getServices().get(0);
		assertThrows(UnsupportedOperationException.class, () -> trustService.getCertificates().add(czSigningCertificate));
		
		TimeDependentValues<TrustServiceStatusAndInformationExtensions> timeDependentValues = trustService.getStatusAndInformationExtensions();
		TrustServiceStatusAndInformationExtensions latest = timeDependentValues.getLatest();
		assertThrows(UnsupportedOperationException.class, () -> latest.getAdditionalServiceInfoUris().add(new String()));
		assertThrows(UnsupportedOperationException.class, () -> latest.getConditionsForQualifiers()
				.add(new ConditionForQualifiers(new CompositeCondition(), new ArrayList<String>())));
		assertThrows(UnsupportedOperationException.class, () -> latest.getNames().put(new String(), new ArrayList<String>()));
		assertThrows(UnsupportedOperationException.class, () -> latest.getServiceSupplyPoints().add(new String()));
		
		assertEquals(Indication.TOTAL_PASSED, czTL.getValidationCacheInfo().getIndication());
		assertNull(czTL.getValidationCacheInfo().getSubIndication());
		assertNotNull(czTL.getValidationCacheInfo().getSigningTime());
		assertNotNull(czTL.getValidationCacheInfo().getSigningCertificate());
		assertEquals(czSigningCertificate, czTL.getValidationCacheInfo().getSigningCertificate());
	}
	
	@Test
	public void noTrustedListCertificateSourceTest() {
		updateTLUrl("src/test/resources/lotlCache/CZ.xml");
		
		tlValidationJob = new TLValidationJob();
		tlValidationJob.setOfflineDataLoader(offlineFileLoader);
		tlValidationJob.setOnlineDataLoader(onlineFileLoader);
		tlValidationJob.setCacheCleaner(cacheCleaner);
		tlValidationJob.setTrustedListSources(czSource);
		tlValidationJob.offlineRefresh();
		
		TLValidationJobSummary summary = tlValidationJob.getSummary();
		
		assertEquals(0, summary.getNumberOfProcessedLOTLs());
		assertEquals(1, summary.getNumberOfProcessedTLs());
		
		List<TLInfo> tlInfos = summary.getOtherTLInfos();
		assertEquals(1, tlInfos.size());
		
		TLInfo czTL = tlInfos.get(0);
		assertNotNull(czTL.getDownloadCacheInfo().getLastLoadingDate());
		assertFalse(czTL.getDownloadCacheInfo().getLastSynchronizationDate().after(czTL.getDownloadCacheInfo().getLastLoadingDate()));
		
		// no TrustedListCertificateSource is present
		assertTrue(czTL.getDownloadCacheInfo().isDesynchronized());
		assertTrue(czTL.getParsingCacheInfo().isDesynchronized());
		assertTrue(czTL.getValidationCacheInfo().isDesynchronized());
	}
	
	@Test
	public void emptyTLTest() {
		Exception exception = assertThrows(NullPointerException.class, () -> {
			tlValidationJob = new TLValidationJob();
			tlValidationJob.setOfflineDataLoader(offlineFileLoader);
			tlValidationJob.setOnlineDataLoader(onlineFileLoader);
			tlValidationJob.setCacheCleaner(cacheCleaner);
			tlValidationJob.setTrustedListSources(new TLSource());
			tlValidationJob.offlineRefresh();
		});
		assertEquals("URL cannot be null.", exception.getMessage());
	}
	
	@Test
	public void lotlTest() {
		TLValidationJob validationJob = getLOTLValidationJob();
		
		TLValidationJobSummary summary = validationJob.getSummary();
		
		assertEquals(1, summary.getNumberOfProcessedLOTLs());
		assertEquals(31, summary.getNumberOfProcessedTLs());
		
		List<TLInfo> otherTLInfos = summary.getOtherTLInfos();
		assertEquals(0, otherTLInfos.size());
		
		List<LOTLInfo> lotlInfos = summary.getLOTLInfos();
		assertEquals(1, lotlInfos.size());
		List<CertificateToken> potentialSigners = lotlInfos.get(0).getValidationCacheInfo().getPotentialSigners();
		assertTrue(Utils.isCollectionNotEmpty(potentialSigners));
		List<CertificateToken> keyStoreCertificates = lotlSource.getCertificateSource().getCertificates();
		assertEquals(keyStoreCertificates.size(), potentialSigners.size());
		for (CertificateToken certificate : potentialSigners) {
			assertTrue(keyStoreCertificates.contains(certificate));
		}
		
		List<TLInfo> tlInfos = lotlInfos.get(0).getTLInfos();
			assertEquals(31, tlInfos.size());
		
		for (TLInfo tlInfo : tlInfos) {
			if (tlInfo.getDownloadCacheInfo().isResultExist()) {
				assertNull(tlInfo.getDownloadCacheInfo().getExceptionMessage());
				assertNull(tlInfo.getDownloadCacheInfo().getExceptionStackTrace());
				assertNull(tlInfo.getParsingCacheInfo().getExceptionMessage());
				assertNull(tlInfo.getParsingCacheInfo().getExceptionStackTrace());
				assertNull(tlInfo.getValidationCacheInfo().getExceptionMessage());
				assertNull(tlInfo.getValidationCacheInfo().getExceptionStackTrace());
				assertTrue(Utils.isCollectionNotEmpty(tlInfo.getValidationCacheInfo().getPotentialSigners()));
			}
		}
		
	}
	
	@Test
	public void emptyLOTLTest() {
		Exception exception = assertThrows(NullPointerException.class, () -> {
			tlValidationJob = new TLValidationJob();
			tlValidationJob.setOfflineDataLoader(offlineFileLoader);
			tlValidationJob.setOnlineDataLoader(onlineFileLoader);
			tlValidationJob.setCacheCleaner(cacheCleaner);
			tlValidationJob.setListOfTrustedListSources(new LOTLSource());
			tlValidationJob.offlineRefresh();
		});
		assertEquals("URL cannot be null.", exception.getMessage());
	}
	
	@Test
	public void lotlValidationSummaryExtractionTimeoutTest() {
		TLValidationJob validationJob = getLOTLValidationJob();
		assertTimeout(ofMillis(50), () -> {
			validationJob.getSummary();
		});
	}
	
	@Test
	public void brokenSigTest() {
		updateTLUrl("src/test/resources/lotlCache/CZ_broken-sig.xml");
		
		TLValidationJobSummary summary = getTLValidationJob().getSummary();
		
		assertEquals(0, summary.getNumberOfProcessedLOTLs());
		assertEquals(1, summary.getNumberOfProcessedTLs());
		
		List<TLInfo> tlInfos = summary.getOtherTLInfos();
		assertEquals(1, tlInfos.size());
		
		TLInfo czTL = tlInfos.get(0);
		
		assertNull(czTL.getDownloadCacheInfo().getExceptionMessage());
		assertNull(czTL.getDownloadCacheInfo().getExceptionStackTrace());
		assertNull(czTL.getParsingCacheInfo().getExceptionMessage());
		assertNull(czTL.getParsingCacheInfo().getExceptionStackTrace());
		assertNull(czTL.getValidationCacheInfo().getExceptionMessage());
		assertNull(czTL.getValidationCacheInfo().getExceptionStackTrace());
		
		assertEquals(Indication.TOTAL_FAILED, czTL.getValidationCacheInfo().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, czTL.getValidationCacheInfo().getSubIndication());
		assertNotNull(czTL.getValidationCacheInfo().getSigningTime());
		assertNotNull(czTL.getValidationCacheInfo().getSigningCertificate());
		assertEquals(czSigningCertificate, czTL.getValidationCacheInfo().getSigningCertificate());
	}
	
	@Test
	public void tlEmptyTest() {
		updateTLUrl("src/test/resources/lotlCache/CZ_empty.xml");
		
		TLValidationJobSummary summary = getTLValidationJob().getSummary();
		
		assertEquals(0, summary.getNumberOfProcessedLOTLs());
		assertEquals(1, summary.getNumberOfProcessedTLs());
		
		List<TLInfo> tlInfos = summary.getOtherTLInfos();
		assertEquals(1, tlInfos.size());
		
		TLInfo czTL = tlInfos.get(0);

		assertFalse(czTL.getDownloadCacheInfo().isResultExist());
		assertTrue(czTL.getDownloadCacheInfo().isError());
		assertNotNull(czTL.getDownloadCacheInfo().getExceptionMessage());
		assertNotNull(czTL.getDownloadCacheInfo().getExceptionStackTrace());
		assertFalse(czTL.getParsingCacheInfo().isResultExist());
		assertNull(czTL.getParsingCacheInfo().getExceptionMessage());
		assertNull(czTL.getParsingCacheInfo().getExceptionStackTrace());
		assertFalse(czTL.getValidationCacheInfo().isResultExist());
		assertNull(czTL.getValidationCacheInfo().getExceptionMessage());
		assertNull(czTL.getValidationCacheInfo().getExceptionStackTrace());
	}
	
	@Test
	public void tlNotParsableTest() {
		updateTLUrl("src/test/resources/lotlCache/CZ_not-parsable.xml");
		
		TLValidationJobSummary summary = getTLValidationJob().getSummary();
		
		assertEquals(0, summary.getNumberOfProcessedLOTLs());
		assertEquals(1, summary.getNumberOfProcessedTLs());
		
		List<TLInfo> tlInfos = summary.getOtherTLInfos();
		assertEquals(1, tlInfos.size());
		
		TLInfo czTL = tlInfos.get(0);

		assertFalse(czTL.getDownloadCacheInfo().isResultExist());
		assertTrue(czTL.getDownloadCacheInfo().isError());
		assertNotNull(czTL.getDownloadCacheInfo().getExceptionMessage());
		assertNotNull(czTL.getDownloadCacheInfo().getExceptionStackTrace());
		assertFalse(czTL.getParsingCacheInfo().isResultExist());
		assertNull(czTL.getParsingCacheInfo().getExceptionMessage());
		assertNull(czTL.getParsingCacheInfo().getExceptionStackTrace());
		assertFalse(czTL.getValidationCacheInfo().isResultExist());
		assertNull(czTL.getValidationCacheInfo().getExceptionMessage());
		assertNull(czTL.getValidationCacheInfo().getExceptionStackTrace());
	}
	
	@Test
	public void tlNotCompliantTest() {
		updateTLUrl("src/test/resources/lotlCache/CZ_not-compliant.xml");
		
		TLValidationJobSummary summary = getTLValidationJob().getSummary();
		
		assertEquals(0, summary.getNumberOfProcessedLOTLs());
		assertEquals(1, summary.getNumberOfProcessedTLs());
		
		List<TLInfo> tlInfos = summary.getOtherTLInfos();
		assertEquals(1, tlInfos.size());
		
		TLInfo czTL = tlInfos.get(0);

		assertTrue(czTL.getDownloadCacheInfo().isResultExist());
		assertNull(czTL.getDownloadCacheInfo().getExceptionMessage());
		assertNull(czTL.getDownloadCacheInfo().getExceptionStackTrace());
		assertFalse(czTL.getParsingCacheInfo().isResultExist());
		assertNotNull(czTL.getParsingCacheInfo().getExceptionMessage());
		assertNotNull(czTL.getParsingCacheInfo().getExceptionStackTrace());
		assertTrue(czTL.getValidationCacheInfo().isResultExist());
		assertNull(czTL.getValidationCacheInfo().getExceptionMessage());
		assertNull(czTL.getValidationCacheInfo().getExceptionStackTrace());
		
		assertEquals(Indication.TOTAL_FAILED, czTL.getValidationCacheInfo().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, czTL.getValidationCacheInfo().getSubIndication());
		
	}
	
	@Test
	public void tlTwoSignaturesTest() {
		updateTLUrl("src/test/resources/lotlCache/CZ_two-sigs.xml");
		
		TLValidationJobSummary summary = getTLValidationJob().getSummary();
		
		assertEquals(0, summary.getNumberOfProcessedLOTLs());
		assertEquals(1, summary.getNumberOfProcessedTLs());
		
		List<TLInfo> tlInfos = summary.getOtherTLInfos();
		assertEquals(1, tlInfos.size());
		
		TLInfo czTL = tlInfos.get(0);

		assertTrue(czTL.getDownloadCacheInfo().isResultExist());
		assertNull(czTL.getDownloadCacheInfo().getExceptionMessage());
		assertNull(czTL.getDownloadCacheInfo().getExceptionStackTrace());
		assertFalse(czTL.getParsingCacheInfo().isResultExist());
		assertNotNull(czTL.getParsingCacheInfo().getExceptionMessage());
		assertNotNull(czTL.getParsingCacheInfo().getExceptionStackTrace());
		assertFalse(czTL.getValidationCacheInfo().isResultExist());
		assertNotNull(czTL.getValidationCacheInfo().getExceptionMessage());
		assertEquals("Number of signatures must be equal to 1 (currently : 2)", czTL.getValidationCacheInfo().getExceptionMessage());
		assertNotNull(czTL.getValidationCacheInfo().getExceptionStackTrace());
		
		assertNull(czTL.getValidationCacheInfo().getIndication());
		assertNull(czTL.getValidationCacheInfo().getSubIndication());
	}
	
	@Test
	public void tlNoSignaturesTest() {
		updateTLUrl("src/test/resources/lotlCache/CZ_no-sig.xml");
		
		TLValidationJobSummary summary = getTLValidationJob().getSummary();
		
		assertEquals(0, summary.getNumberOfProcessedLOTLs());
		assertEquals(1, summary.getNumberOfProcessedTLs());
		
		List<TLInfo> tlInfos = summary.getOtherTLInfos();
		assertEquals(1, tlInfos.size());
		
		TLInfo czTL = tlInfos.get(0);

		assertTrue(czTL.getDownloadCacheInfo().isResultExist());
		assertNull(czTL.getDownloadCacheInfo().getExceptionMessage());
		assertNull(czTL.getDownloadCacheInfo().getExceptionStackTrace());
		assertTrue(czTL.getParsingCacheInfo().isResultExist());
		assertNull(czTL.getParsingCacheInfo().getExceptionMessage());
		assertNull(czTL.getParsingCacheInfo().getExceptionStackTrace());
		assertFalse(czTL.getValidationCacheInfo().isResultExist());
		assertNotNull(czTL.getValidationCacheInfo().getExceptionMessage());
		assertEquals("Number of signatures must be equal to 1 (currently : 0)", czTL.getValidationCacheInfo().getExceptionMessage());
		assertNotNull(czTL.getValidationCacheInfo().getExceptionStackTrace());
		
		assertNull(czTL.getValidationCacheInfo().getIndication());
		assertNull(czTL.getValidationCacheInfo().getSubIndication());
	}
	
	@Test
	public void tlPdfTest() {
		updateTLUrl("src/test/resources/lotlCache/CZ.pdf");
		
		TLValidationJobSummary summary = getTLValidationJob().getSummary();
		List<TLInfo> tlInfos = summary.getOtherTLInfos();
		TLInfo czTL = tlInfos.get(0);
		
		assertFalse(czTL.getDownloadCacheInfo().isResultExist());
		assertNotNull(czTL.getDownloadCacheInfo().getExceptionMessage());
		assertNotNull(czTL.getDownloadCacheInfo().getExceptionStackTrace());
		assertFalse(czTL.getParsingCacheInfo().isResultExist());
		assertNull(czTL.getParsingCacheInfo().getExceptionMessage());
		assertNull(czTL.getParsingCacheInfo().getExceptionStackTrace());
		assertFalse(czTL.getValidationCacheInfo().isResultExist());
		assertNull(czTL.getValidationCacheInfo().getExceptionMessage());
		assertNull(czTL.getValidationCacheInfo().getExceptionStackTrace());
	}
	
	@Test
	public void lotlBrokenSigTest() {
		updateLOTLUrl("src/test/resources/lotlCache/eu-lotl_broken-sig.xml");
		
		TLValidationJobSummary summary = getLOTLValidationJob().getSummary();
		List<LOTLInfo> tlInfos = summary.getLOTLInfos();
		LOTLInfo lotlInfo = tlInfos.get(0);
		
		assertTrue(lotlInfo.getDownloadCacheInfo().isResultExist());
		assertNull(lotlInfo.getDownloadCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getDownloadCacheInfo().getExceptionStackTrace());
		assertTrue(lotlInfo.getParsingCacheInfo().isResultExist());
		assertNull(lotlInfo.getParsingCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getParsingCacheInfo().getExceptionStackTrace());
		assertTrue(lotlInfo.getValidationCacheInfo().isResultExist());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionStackTrace());
		
		assertEquals(Indication.TOTAL_FAILED, lotlInfo.getValidationCacheInfo().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, lotlInfo.getValidationCacheInfo().getSubIndication());
		assertNotNull(lotlInfo.getValidationCacheInfo().getSigningTime());
		assertNotNull(lotlInfo.getValidationCacheInfo().getSigningCertificate());
	}
	
	@Test
	public void lotlNotParsableTest() {
		updateLOTLUrl("src/test/resources/lotlCache/eu-lotl_not-parsable.xml");
		
		TLValidationJobSummary summary = getLOTLValidationJob().getSummary();
		List<LOTLInfo> tlInfos = summary.getLOTLInfos();
		LOTLInfo lotlInfo = tlInfos.get(0);
		
		assertEquals(0, lotlInfo.getTLInfos().size());
		
		assertFalse(lotlInfo.getDownloadCacheInfo().isResultExist());
		assertNotNull(lotlInfo.getDownloadCacheInfo().getExceptionMessage());
		assertNotNull(lotlInfo.getDownloadCacheInfo().getExceptionStackTrace());
		assertFalse(lotlInfo.getParsingCacheInfo().isResultExist());
		assertNull(lotlInfo.getParsingCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getParsingCacheInfo().getExceptionStackTrace());
		assertFalse(lotlInfo.getValidationCacheInfo().isResultExist());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionStackTrace());
	}
	
	@Test
	public void lotlNonCompliantTest() {
		updateLOTLUrl("src/test/resources/lotlCache/eu-lotl_non-compliant.xml");
		
		TLValidationJobSummary summary = getLOTLValidationJob().getSummary();
		List<LOTLInfo> tlInfos = summary.getLOTLInfos();
		LOTLInfo lotlInfo = tlInfos.get(0);
		
		assertEquals(0, lotlInfo.getTLInfos().size());
		
		assertTrue(lotlInfo.getDownloadCacheInfo().isResultExist());
		assertNull(lotlInfo.getDownloadCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getDownloadCacheInfo().getExceptionStackTrace());
		assertFalse(lotlInfo.getParsingCacheInfo().isResultExist());
		assertNotNull(lotlInfo.getParsingCacheInfo().getExceptionMessage());
		assertNotNull(lotlInfo.getParsingCacheInfo().getExceptionStackTrace());
		assertTrue(lotlInfo.getValidationCacheInfo().isResultExist());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionStackTrace());
	}
	
	@Test
	public void lotlXmlDeclarationRemovedTest() {
		updateLOTLUrl("src/test/resources/lotlCache/eu-lotl_xml-directive-removed.xml");
		
		TLValidationJobSummary summary = getLOTLValidationJob().getSummary();
		List<LOTLInfo> tlInfos = summary.getLOTLInfos();
		LOTLInfo lotlInfo = tlInfos.get(0);
		
		assertEquals(31, lotlInfo.getTLInfos().size());

		assertTrue(lotlInfo.getDownloadCacheInfo().isResultExist());
		assertNull(lotlInfo.getDownloadCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getDownloadCacheInfo().getExceptionStackTrace());
		assertTrue(lotlInfo.getParsingCacheInfo().isResultExist());
		assertNull(lotlInfo.getParsingCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getParsingCacheInfo().getExceptionStackTrace());
		assertTrue(lotlInfo.getValidationCacheInfo().isResultExist());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionStackTrace());
		
		assertEquals(Indication.TOTAL_PASSED, lotlInfo.getValidationCacheInfo().getIndication());
		assertNull(lotlInfo.getValidationCacheInfo().getSubIndication());
		assertNotNull(lotlInfo.getValidationCacheInfo().getSigningTime());
		assertNotNull(lotlInfo.getValidationCacheInfo().getSigningCertificate());
	}
	
	@Test
	public void pivotTest() {
		updatePivotUrl("src/test/resources/lotlCache/tl_pivot_247_mp.xml");
		
		TLValidationJobSummary summary = getLOTLValidationJob().getSummary();
		List<LOTLInfo> tlInfos = summary.getLOTLInfos();
		LOTLInfo lotlInfo = tlInfos.get(0);
		
		assertEquals(4, lotlInfo.getPivotInfos().size());
		assertEquals(31, lotlInfo.getTLInfos().size());
		
		for (PivotInfo pivotInfo : lotlInfo.getPivotInfos()) {
			assertTrue(pivotInfo.getDownloadCacheInfo().isResultExist());
			assertNull(pivotInfo.getDownloadCacheInfo().getExceptionMessage());
			assertNull(pivotInfo.getDownloadCacheInfo().getExceptionStackTrace());
			assertTrue(pivotInfo.getParsingCacheInfo().isResultExist());
			assertNull(pivotInfo.getParsingCacheInfo().getExceptionMessage());
			assertNull(pivotInfo.getParsingCacheInfo().getExceptionStackTrace());
			assertTrue(pivotInfo.getValidationCacheInfo().isResultExist());
			assertNull(pivotInfo.getValidationCacheInfo().getExceptionMessage());
			assertNull(pivotInfo.getValidationCacheInfo().getExceptionStackTrace());
			
			assertEquals(Indication.TOTAL_PASSED, pivotInfo.getValidationCacheInfo().getIndication());
			assertNull(pivotInfo.getValidationCacheInfo().getSubIndication());
			assertNotNull(pivotInfo.getValidationCacheInfo().getSigningTime());
			assertNotNull(pivotInfo.getValidationCacheInfo().getSigningCertificate());
			
			assertTrue(Utils.isMapNotEmpty(pivotInfo.getCertificateStatusMap()));
			assertNotNull(pivotInfo.getLOTLLocation());
		}
		
		PivotInfo firstPivotInfo = lotlInfo.getPivotInfos().get(0);
		Map<CertificateToken, CertificatePivotStatus> certificateStatusMap = firstPivotInfo.getCertificateStatusMap();
		assertEquals(4, certificateStatusMap.size());
		int addedCerts = 0;
		int staticCerts = 0;
		int removedCerts = 0;
		for (CertificatePivotStatus certificatePivotStatus : certificateStatusMap.values()) {
			switch (certificatePivotStatus) {
				case ADDED:
					addedCerts++;
					break;
				case NOT_CHANGED:
					staticCerts++;
					break;
				case REMOVED:
					removedCerts++;
					break;
			}
		}
		assertEquals(3, addedCerts);
		assertEquals(1, staticCerts);
		assertEquals(0, removedCerts);
		
	}
	
	@Test
	public void pivotBrokenSigTest() {
		updatePivotUrl("src/test/resources/lotlCache/tl_pivot_247_mp_broken-sig.xml");
		
		TLValidationJobSummary summary = getLOTLValidationJob().getSummary();
		List<LOTLInfo> tlInfos = summary.getLOTLInfos();
		LOTLInfo lotlInfo = tlInfos.get(0);
		
		assertEquals(4, lotlInfo.getPivotInfos().size());
		assertEquals(31, lotlInfo.getTLInfos().size());
		
		assertTrue(lotlInfo.getDownloadCacheInfo().isResultExist());
		assertNull(lotlInfo.getDownloadCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getDownloadCacheInfo().getExceptionStackTrace());
		assertTrue(lotlInfo.getParsingCacheInfo().isResultExist());
		assertNull(lotlInfo.getParsingCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getParsingCacheInfo().getExceptionStackTrace());
		assertTrue(lotlInfo.getValidationCacheInfo().isResultExist());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionStackTrace());
		
		assertEquals(Indication.TOTAL_FAILED, lotlInfo.getValidationCacheInfo().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, lotlInfo.getValidationCacheInfo().getSubIndication());
		assertNotNull(lotlInfo.getValidationCacheInfo().getSigningTime());
		assertNotNull(lotlInfo.getValidationCacheInfo().getSigningCertificate());
		
		PivotInfo pivotInfo = lotlInfo.getPivotInfos().get(3);
		
		assertTrue(pivotInfo.getDownloadCacheInfo().isResultExist());
		assertNull(pivotInfo.getDownloadCacheInfo().getExceptionMessage());
		assertNull(pivotInfo.getDownloadCacheInfo().getExceptionStackTrace());
		assertTrue(pivotInfo.getParsingCacheInfo().isResultExist());
		assertNull(pivotInfo.getParsingCacheInfo().getExceptionMessage());
		assertNull(pivotInfo.getParsingCacheInfo().getExceptionStackTrace());
		assertTrue(pivotInfo.getValidationCacheInfo().isResultExist());
		assertNull(pivotInfo.getValidationCacheInfo().getExceptionMessage());
		assertNull(pivotInfo.getValidationCacheInfo().getExceptionStackTrace());
		
		assertEquals(Indication.TOTAL_FAILED, pivotInfo.getValidationCacheInfo().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, pivotInfo.getValidationCacheInfo().getSubIndication());
		assertNotNull(pivotInfo.getValidationCacheInfo().getSigningTime());
		assertNotNull(pivotInfo.getValidationCacheInfo().getSigningCertificate());
	}
	
	@Test
	public void intermediatePivotBrokenSigTest() {
		updatePivotUrl("src/test/resources/lotlCache/tl_pivot_247_mp.xml");
		
		urlMap.put("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-191-mp.xml", 
				new FileDocument("src/test/resources/lotlCache/tl_pivot_191_mp_broken-sig.xml"));
		
		TLValidationJobSummary summary = getLOTLValidationJob().getSummary();
		List<LOTLInfo> tlInfos = summary.getLOTLInfos();
		LOTLInfo lotlInfo = tlInfos.get(0);
		
		assertEquals(4, lotlInfo.getPivotInfos().size());
		assertEquals(31, lotlInfo.getTLInfos().size());
		
		assertTrue(lotlInfo.getDownloadCacheInfo().isResultExist());
		assertNull(lotlInfo.getDownloadCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getDownloadCacheInfo().getExceptionStackTrace());
		assertTrue(lotlInfo.getParsingCacheInfo().isResultExist());
		assertNull(lotlInfo.getParsingCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getParsingCacheInfo().getExceptionStackTrace());
		assertTrue(lotlInfo.getValidationCacheInfo().isResultExist());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionStackTrace());
		
		assertEquals(Indication.INDETERMINATE, lotlInfo.getValidationCacheInfo().getIndication());
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, lotlInfo.getValidationCacheInfo().getSubIndication());
		assertNotNull(lotlInfo.getValidationCacheInfo().getSigningTime());
		assertNotNull(lotlInfo.getValidationCacheInfo().getSigningCertificate());
		
		PivotInfo brokenPivotInfo = lotlInfo.getPivotInfos().get(1);
		
		assertTrue(brokenPivotInfo.getDownloadCacheInfo().isResultExist());
		assertNull(brokenPivotInfo.getDownloadCacheInfo().getExceptionMessage());
		assertNull(brokenPivotInfo.getDownloadCacheInfo().getExceptionStackTrace());
		assertTrue(brokenPivotInfo.getParsingCacheInfo().isResultExist());
		assertNull(brokenPivotInfo.getParsingCacheInfo().getExceptionMessage());
		assertNull(brokenPivotInfo.getParsingCacheInfo().getExceptionStackTrace());
		assertTrue(brokenPivotInfo.getValidationCacheInfo().isResultExist());
		assertNull(brokenPivotInfo.getValidationCacheInfo().getExceptionMessage());
		assertNull(brokenPivotInfo.getValidationCacheInfo().getExceptionStackTrace());
		
		assertEquals(Indication.TOTAL_FAILED, brokenPivotInfo.getValidationCacheInfo().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, brokenPivotInfo.getValidationCacheInfo().getSubIndication());
		assertNotNull(brokenPivotInfo.getValidationCacheInfo().getSigningTime());
		assertNotNull(brokenPivotInfo.getValidationCacheInfo().getSigningCertificate());
		
		PivotInfo firstpivotInfo = lotlInfo.getPivotInfos().get(0);
		
		assertTrue(firstpivotInfo.getDownloadCacheInfo().isResultExist());
		assertNull(firstpivotInfo.getDownloadCacheInfo().getExceptionMessage());
		assertNull(firstpivotInfo.getDownloadCacheInfo().getExceptionStackTrace());
		assertTrue(firstpivotInfo.getParsingCacheInfo().isResultExist());
		assertNull(firstpivotInfo.getParsingCacheInfo().getExceptionMessage());
		assertNull(firstpivotInfo.getParsingCacheInfo().getExceptionStackTrace());
		assertTrue(firstpivotInfo.getValidationCacheInfo().isResultExist());
		assertNull(firstpivotInfo.getValidationCacheInfo().getExceptionMessage());
		assertNull(firstpivotInfo.getValidationCacheInfo().getExceptionStackTrace());
		
		assertEquals(Indication.TOTAL_PASSED, firstpivotInfo.getValidationCacheInfo().getIndication());
		assertNull(firstpivotInfo.getValidationCacheInfo().getSubIndication());
		assertNotNull(firstpivotInfo.getValidationCacheInfo().getSigningTime());
		assertNotNull(firstpivotInfo.getValidationCacheInfo().getSigningCertificate());
	}
	
	@Test
	public void missingPivotTest() {
		updatePivotUrl("src/test/resources/lotlCache/tl_pivot_247_mp_missing-pivot.xml");
		
		TLValidationJobSummary summary = getLOTLValidationJob().getSummary();
		List<LOTLInfo> tlInfos = summary.getLOTLInfos();
		LOTLInfo lotlInfo = tlInfos.get(0);
		
		assertEquals(4, lotlInfo.getPivotInfos().size());
		
		PivotInfo missingPivotInfo = lotlInfo.getPivotInfos().get(2);
		assertFalse(missingPivotInfo.getDownloadCacheInfo().isResultExist());
		assertNotNull(missingPivotInfo.getDownloadCacheInfo().getExceptionMessage());
		assertNotNull(missingPivotInfo.getDownloadCacheInfo().getExceptionStackTrace());
		assertFalse(missingPivotInfo.getParsingCacheInfo().isResultExist());
		assertNull(missingPivotInfo.getParsingCacheInfo().getExceptionMessage());
		assertNull(missingPivotInfo.getParsingCacheInfo().getExceptionStackTrace());
		assertFalse(missingPivotInfo.getValidationCacheInfo().isResultExist());
		assertNull(missingPivotInfo.getValidationCacheInfo().getExceptionMessage());
		assertNull(missingPivotInfo.getValidationCacheInfo().getExceptionStackTrace());
		
		assertTrue(lotlInfo.getDownloadCacheInfo().isResultExist());
		assertNull(lotlInfo.getDownloadCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getDownloadCacheInfo().getExceptionStackTrace());
		assertTrue(lotlInfo.getParsingCacheInfo().isResultExist());
		assertNull(lotlInfo.getParsingCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getParsingCacheInfo().getExceptionStackTrace());
		assertTrue(lotlInfo.getValidationCacheInfo().isResultExist());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionStackTrace());

		assertEquals(Indication.TOTAL_FAILED, lotlInfo.getValidationCacheInfo().getIndication());
		assertEquals(SubIndication.HASH_FAILURE, lotlInfo.getValidationCacheInfo().getSubIndication());
		assertNotNull(lotlInfo.getValidationCacheInfo().getSigningTime());
		assertNotNull(lotlInfo.getValidationCacheInfo().getSigningCertificate());
	}
	
	@Test
	public void pivotNoSigTest() {
		updatePivotUrl("src/test/resources/lotlCache/tl_pivot_247_mp_no-sig.xml");
		
		TLValidationJobSummary summary = getLOTLValidationJob().getSummary();
		List<LOTLInfo> tlInfos = summary.getLOTLInfos();
		LOTLInfo lotlInfo = tlInfos.get(0);
		
		assertEquals(4, lotlInfo.getPivotInfos().size());
		
		PivotInfo pivotInfo = lotlInfo.getPivotInfos().get(3);
		assertTrue(pivotInfo.getDownloadCacheInfo().isResultExist());
		assertNull(pivotInfo.getDownloadCacheInfo().getExceptionMessage());
		assertNull(pivotInfo.getDownloadCacheInfo().getExceptionStackTrace());
		assertTrue(pivotInfo.getParsingCacheInfo().isResultExist());
		assertNull(pivotInfo.getParsingCacheInfo().getExceptionMessage());
		assertNull(pivotInfo.getParsingCacheInfo().getExceptionStackTrace());
		assertFalse(pivotInfo.getValidationCacheInfo().isResultExist());
		assertNotNull(pivotInfo.getValidationCacheInfo().getExceptionMessage());
		assertNotNull(pivotInfo.getValidationCacheInfo().getExceptionStackTrace());
	}
	
	@Test
	public void intermediatePivotNoSigTest() {
		updatePivotUrl("src/test/resources/lotlCache/tl_pivot_247_mp.xml");
		
		urlMap.put("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-191-mp.xml", 
				new FileDocument("src/test/resources/lotlCache/tl_pivot_191_mp_no-sig.xml"));
		
		TLValidationJobSummary summary = getLOTLValidationJob().getSummary();
		List<LOTLInfo> tlInfos = summary.getLOTLInfos();
		LOTLInfo lotlInfo = tlInfos.get(0);
		
		assertEquals(4, lotlInfo.getPivotInfos().size());
		
		assertTrue(lotlInfo.getDownloadCacheInfo().isResultExist());
		assertNull(lotlInfo.getDownloadCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getDownloadCacheInfo().getExceptionStackTrace());
		assertTrue(lotlInfo.getParsingCacheInfo().isResultExist());
		assertNull(lotlInfo.getParsingCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getParsingCacheInfo().getExceptionStackTrace());
		assertTrue(lotlInfo.getValidationCacheInfo().isResultExist());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionStackTrace());
		
		assertEquals(Indication.INDETERMINATE, lotlInfo.getValidationCacheInfo().getIndication());
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, lotlInfo.getValidationCacheInfo().getSubIndication());
		assertNotNull(lotlInfo.getValidationCacheInfo().getSigningTime());
		assertNotNull(lotlInfo.getValidationCacheInfo().getSigningCertificate());
		
		PivotInfo pivotNoSigInfo = lotlInfo.getPivotInfos().get(1);
		assertTrue(pivotNoSigInfo.getDownloadCacheInfo().isResultExist());
		assertNull(pivotNoSigInfo.getDownloadCacheInfo().getExceptionMessage());
		assertNull(pivotNoSigInfo.getDownloadCacheInfo().getExceptionStackTrace());
		assertTrue(pivotNoSigInfo.getParsingCacheInfo().isResultExist());
		assertNull(pivotNoSigInfo.getParsingCacheInfo().getExceptionMessage());
		assertNull(pivotNoSigInfo.getParsingCacheInfo().getExceptionStackTrace());
		assertFalse(pivotNoSigInfo.getValidationCacheInfo().isResultExist());
		assertNotNull(pivotNoSigInfo.getValidationCacheInfo().getExceptionMessage());
		assertNotNull(pivotNoSigInfo.getValidationCacheInfo().getExceptionStackTrace());
		
		PivotInfo firstpivotInfo = lotlInfo.getPivotInfos().get(0);
		
		assertTrue(firstpivotInfo.getDownloadCacheInfo().isResultExist());
		assertNull(firstpivotInfo.getDownloadCacheInfo().getExceptionMessage());
		assertNull(firstpivotInfo.getDownloadCacheInfo().getExceptionStackTrace());
		assertTrue(firstpivotInfo.getParsingCacheInfo().isResultExist());
		assertNull(firstpivotInfo.getParsingCacheInfo().getExceptionMessage());
		assertNull(firstpivotInfo.getParsingCacheInfo().getExceptionStackTrace());
		assertTrue(firstpivotInfo.getValidationCacheInfo().isResultExist());
		assertNull(firstpivotInfo.getValidationCacheInfo().getExceptionMessage());
		assertNull(firstpivotInfo.getValidationCacheInfo().getExceptionStackTrace());
		
		assertEquals(Indication.TOTAL_PASSED, firstpivotInfo.getValidationCacheInfo().getIndication());
		assertNull(firstpivotInfo.getValidationCacheInfo().getSubIndication());
		assertNotNull(firstpivotInfo.getValidationCacheInfo().getSigningTime());
		assertNotNull(firstpivotInfo.getValidationCacheInfo().getSigningCertificate());
	}
	
	@Test
	public void pivotNotParsableTest() {
		updatePivotUrl("src/test/resources/lotlCache/tl_pivot_247_mp_not-parsable.xml");
		
		TLValidationJobSummary summary = getLOTLValidationJob().getSummary();
		List<LOTLInfo> tlInfos = summary.getLOTLInfos();
		LOTLInfo lotlInfo = tlInfos.get(0);
		
		assertEquals(0, lotlInfo.getPivotInfos().size());

		assertFalse(lotlInfo.getDownloadCacheInfo().isResultExist());
		assertNotNull(lotlInfo.getDownloadCacheInfo().getExceptionMessage());
		assertNotNull(lotlInfo.getDownloadCacheInfo().getExceptionStackTrace());
		assertFalse(lotlInfo.getParsingCacheInfo().isResultExist());
		assertNull(lotlInfo.getParsingCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getParsingCacheInfo().getExceptionStackTrace());
		assertFalse(lotlInfo.getValidationCacheInfo().isResultExist());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionStackTrace());
	}
	
	@Test
	public void intermediatePivotNotParsableTest() {
		updatePivotUrl("src/test/resources/lotlCache/tl_pivot_247_mp.xml");
		
		urlMap.put("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-191-mp.xml", 
				new FileDocument("src/test/resources/lotlCache/tl_pivot_191_mp_not-parsable.xml"));
		
		TLValidationJobSummary summary = getLOTLValidationJob().getSummary();
		List<LOTLInfo> tlInfos = summary.getLOTLInfos();
		LOTLInfo lotlInfo = tlInfos.get(0);
		
		assertEquals(4, lotlInfo.getPivotInfos().size());
		
		assertTrue(lotlInfo.getDownloadCacheInfo().isResultExist());
		assertNull(lotlInfo.getDownloadCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getDownloadCacheInfo().getExceptionStackTrace());
		assertTrue(lotlInfo.getParsingCacheInfo().isResultExist());
		assertNull(lotlInfo.getParsingCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getParsingCacheInfo().getExceptionStackTrace());
		assertTrue(lotlInfo.getValidationCacheInfo().isResultExist());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionStackTrace());
		
		assertEquals(Indication.INDETERMINATE, lotlInfo.getValidationCacheInfo().getIndication());
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, lotlInfo.getValidationCacheInfo().getSubIndication());
		assertNotNull(lotlInfo.getValidationCacheInfo().getSigningTime());
		assertNotNull(lotlInfo.getValidationCacheInfo().getSigningCertificate());
		
		PivotInfo pivotNoSigInfo = lotlInfo.getPivotInfos().get(1);
		assertFalse(pivotNoSigInfo.getDownloadCacheInfo().isResultExist());
		assertNotNull(pivotNoSigInfo.getDownloadCacheInfo().getExceptionMessage());
		assertNotNull(pivotNoSigInfo.getDownloadCacheInfo().getExceptionStackTrace());
		assertFalse(pivotNoSigInfo.getParsingCacheInfo().isResultExist());
		assertNull(pivotNoSigInfo.getParsingCacheInfo().getExceptionMessage());
		assertNull(pivotNoSigInfo.getParsingCacheInfo().getExceptionStackTrace());
		assertFalse(pivotNoSigInfo.getValidationCacheInfo().isResultExist());
		assertNull(pivotNoSigInfo.getValidationCacheInfo().getExceptionMessage());
		assertNull(pivotNoSigInfo.getValidationCacheInfo().getExceptionStackTrace());
		
		PivotInfo firstpivotInfo = lotlInfo.getPivotInfos().get(0);
		
		assertTrue(firstpivotInfo.getDownloadCacheInfo().isResultExist());
		assertNull(firstpivotInfo.getDownloadCacheInfo().getExceptionMessage());
		assertNull(firstpivotInfo.getDownloadCacheInfo().getExceptionStackTrace());
		assertTrue(firstpivotInfo.getParsingCacheInfo().isResultExist());
		assertNull(firstpivotInfo.getParsingCacheInfo().getExceptionMessage());
		assertNull(firstpivotInfo.getParsingCacheInfo().getExceptionStackTrace());
		assertTrue(firstpivotInfo.getValidationCacheInfo().isResultExist());
		assertNull(firstpivotInfo.getValidationCacheInfo().getExceptionMessage());
		assertNull(firstpivotInfo.getValidationCacheInfo().getExceptionStackTrace());
		
		assertEquals(Indication.TOTAL_PASSED, firstpivotInfo.getValidationCacheInfo().getIndication());
		assertNull(firstpivotInfo.getValidationCacheInfo().getSubIndication());
		assertNotNull(firstpivotInfo.getValidationCacheInfo().getSigningTime());
		assertNotNull(firstpivotInfo.getValidationCacheInfo().getSigningCertificate());
	}
	
	@Test
	public void pivotUTF8WithBomTest() {
		updatePivotUrl("src/test/resources/lotlCache/tl_pivot_247_mp_with-bom.xml");
		
		TLValidationJobSummary summary = getLOTLValidationJob().getSummary();
		List<LOTLInfo> tlInfos = summary.getLOTLInfos();
		LOTLInfo lotlInfo = tlInfos.get(0);
		
		assertEquals(4, lotlInfo.getPivotInfos().size());
		
		for (PivotInfo pivotInfo : lotlInfo.getPivotInfos()) {
			assertTrue(pivotInfo.getDownloadCacheInfo().isResultExist());
			assertNull(pivotInfo.getDownloadCacheInfo().getExceptionMessage());
			assertNull(pivotInfo.getDownloadCacheInfo().getExceptionStackTrace());
			assertTrue(pivotInfo.getParsingCacheInfo().isResultExist());
			assertNull(pivotInfo.getParsingCacheInfo().getExceptionMessage());
			assertNull(pivotInfo.getParsingCacheInfo().getExceptionStackTrace());
			assertTrue(pivotInfo.getValidationCacheInfo().isResultExist());
			assertNull(pivotInfo.getValidationCacheInfo().getExceptionMessage());
			assertNull(pivotInfo.getValidationCacheInfo().getExceptionStackTrace());
			
			assertEquals(Indication.TOTAL_PASSED, pivotInfo.getValidationCacheInfo().getIndication());
			assertNull(pivotInfo.getValidationCacheInfo().getSubIndication());
			assertNotNull(pivotInfo.getValidationCacheInfo().getSigningTime());
			assertNotNull(pivotInfo.getValidationCacheInfo().getSigningCertificate());
		}
	}
	
	@Test
	public void pivotWithSpacesTest() {
		updatePivotUrl("src/test/resources/lotlCache/tl_pivot_247_mp_with-spaces.xml");
		
		TLValidationJobSummary summary = getLOTLValidationJob().getSummary();
		List<LOTLInfo> tlInfos = summary.getLOTLInfos();
		LOTLInfo lotlInfo = tlInfos.get(0);
		
		assertEquals(4, lotlInfo.getPivotInfos().size());
		
		for (PivotInfo pivotInfo : lotlInfo.getPivotInfos()) {
			assertTrue(pivotInfo.getDownloadCacheInfo().isResultExist());
			assertNull(pivotInfo.getDownloadCacheInfo().getExceptionMessage());
			assertNull(pivotInfo.getDownloadCacheInfo().getExceptionStackTrace());
			assertTrue(pivotInfo.getParsingCacheInfo().isResultExist());
			assertNull(pivotInfo.getParsingCacheInfo().getExceptionMessage());
			assertNull(pivotInfo.getParsingCacheInfo().getExceptionStackTrace());
			assertTrue(pivotInfo.getValidationCacheInfo().isResultExist());
			assertNull(pivotInfo.getValidationCacheInfo().getExceptionMessage());
			assertNull(pivotInfo.getValidationCacheInfo().getExceptionStackTrace());
			
			assertEquals(Indication.TOTAL_PASSED, pivotInfo.getValidationCacheInfo().getIndication());
			assertNull(pivotInfo.getValidationCacheInfo().getSubIndication());
			assertNotNull(pivotInfo.getValidationCacheInfo().getSigningTime());
			assertNotNull(pivotInfo.getValidationCacheInfo().getSigningCertificate());
		}
	}
	
	@Test
	public void wrongPivotKeystoreTest() throws IOException {
		updatePivotUrl("src/test/resources/lotlCache/tl_pivot_247_mp_with-spaces.xml");
		lotlSource.setCertificateSource(new KeyStoreCertificateSource(new File("src/test/resources/keystore_corrupted.p12"), "PKCS12", "dss-password"));
		
		TLValidationJobSummary summary = getLOTLValidationJob().getSummary();
		List<LOTLInfo> tlInfos = summary.getLOTLInfos();
		LOTLInfo lotlInfo = tlInfos.get(0);
		
		assertEquals(4, lotlInfo.getPivotInfos().size());
		
		for (PivotInfo pivotInfo : lotlInfo.getPivotInfos()) {
			assertTrue(pivotInfo.getDownloadCacheInfo().isResultExist());
			assertNull(pivotInfo.getDownloadCacheInfo().getExceptionMessage());
			assertNull(pivotInfo.getDownloadCacheInfo().getExceptionStackTrace());
			assertTrue(pivotInfo.getParsingCacheInfo().isResultExist());
			assertNull(pivotInfo.getParsingCacheInfo().getExceptionMessage());
			assertNull(pivotInfo.getParsingCacheInfo().getExceptionStackTrace());
			assertTrue(pivotInfo.getValidationCacheInfo().isResultExist());
			assertNull(pivotInfo.getValidationCacheInfo().getExceptionMessage());
			assertNull(pivotInfo.getValidationCacheInfo().getExceptionStackTrace());
			
			assertEquals(Indication.INDETERMINATE, pivotInfo.getValidationCacheInfo().getIndication());
			assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, pivotInfo.getValidationCacheInfo().getSubIndication());
			assertNotNull(pivotInfo.getValidationCacheInfo().getSigningTime());
			assertNotNull(pivotInfo.getValidationCacheInfo().getSigningCertificate());
		}
	}
	
	@Test
	public void lotlCorruptedKeystoreTest() throws IOException {
		updateLOTLUrl("src/test/resources/lotlCache/eu-lotl_original.xml");
		lotlSource.setCertificateSource(new KeyStoreCertificateSource(new File("src/test/resources/keystore_corrupted.p12"), "PKCS12", "dss-password"));
		
		TLValidationJobSummary summary = getLOTLValidationJob().getSummary();
		List<LOTLInfo> tlInfos = summary.getLOTLInfos();
		LOTLInfo lotlInfo = tlInfos.get(0);

		assertTrue(lotlInfo.getDownloadCacheInfo().isResultExist());
		assertNull(lotlInfo.getDownloadCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getDownloadCacheInfo().getExceptionStackTrace());
		assertTrue(lotlInfo.getParsingCacheInfo().isResultExist());
		assertNull(lotlInfo.getParsingCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getParsingCacheInfo().getExceptionStackTrace());
		assertTrue(lotlInfo.getValidationCacheInfo().isResultExist());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionMessage());
		assertNull(lotlInfo.getValidationCacheInfo().getExceptionStackTrace());

		assertEquals(Indication.INDETERMINATE, lotlInfo.getValidationCacheInfo().getIndication());
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, lotlInfo.getValidationCacheInfo().getSubIndication());
		assertNotNull(lotlInfo.getValidationCacheInfo().getSigningTime());
		assertNotNull(lotlInfo.getValidationCacheInfo().getSigningCertificate());
	}
	
	@Test
	public void peruvianTSLTest() {
		LOTLSource peruvianLotlSource = getPeruvianLotlSource();
		
		tlValidationJob = new TLValidationJob();
		tlValidationJob.setOfflineDataLoader(offlineFileLoader);
		tlValidationJob.setListOfTrustedListSources(peruvianLotlSource);
		tlValidationJob.offlineRefresh();
		
		TLValidationJobSummary summary = tlValidationJob.getSummary();
		List<LOTLInfo> lotlInfos = summary.getLOTLInfos();
		
		assertEquals(1, lotlInfos.size());
		LOTLInfo peruvianLOTL = lotlInfos.get(0);
		assertTrue(peruvianLOTL.getDownloadCacheInfo().isResultExist());
		assertFalse(peruvianLOTL.getDownloadCacheInfo().isError());
		assertTrue(peruvianLOTL.getParsingCacheInfo().isResultExist());
		assertFalse(peruvianLOTL.getParsingCacheInfo().isError());
		assertTrue(peruvianLOTL.getValidationCacheInfo().isResultExist());
		assertFalse(peruvianLOTL.getValidationCacheInfo().isError());
		assertEquals(Indication.TOTAL_PASSED, peruvianLOTL.getValidationCacheInfo().getIndication());
		
		assertEquals(1, peruvianLOTL.getTLInfos().size());
		TLInfo peruvianTL = peruvianLOTL.getTLInfos().get(0);
		assertTrue(peruvianTL.getDownloadCacheInfo().isResultExist());
		assertFalse(peruvianTL.getDownloadCacheInfo().isError());
		assertFalse(peruvianTL.getParsingCacheInfo().isResultExist());
		assertTrue(peruvianTL.getParsingCacheInfo().isError());
		assertTrue(peruvianTL.getValidationCacheInfo().isResultExist());
		assertFalse(peruvianTL.getValidationCacheInfo().isError());
		assertEquals(Indication.TOTAL_PASSED, peruvianTL.getValidationCacheInfo().getIndication());
	}
	
	@Test
	public void twoLOTLTest() {
		LOTLSource peruvianLotlSource = getPeruvianLotlSource();
		
		tlValidationJob = new TLValidationJob();
		tlValidationJob.setOfflineDataLoader(offlineFileLoader);
		tlValidationJob.setListOfTrustedListSources(lotlSource, peruvianLotlSource);
		tlValidationJob.offlineRefresh();
		
		TLValidationJobSummary summary = tlValidationJob.getSummary();
		List<LOTLInfo> lotlInfos = summary.getLOTLInfos();
		assertEquals(2, lotlInfos.size());
		for (LOTLInfo lotlInfo : lotlInfos) {
			if (LOTL_URL.equals(lotlInfo.getUrl())) {
				assertEquals(31, lotlInfo.getTLInfos().size());
			} else {
				assertEquals(1, lotlInfo.getTLInfos().size());
			}
			assertTrue(lotlInfo.getDownloadCacheInfo().isResultExist());
			assertFalse(lotlInfo.getDownloadCacheInfo().isError());
			assertTrue(lotlInfo.getParsingCacheInfo().isResultExist());
			assertFalse(lotlInfo.getParsingCacheInfo().isError());
			assertTrue(lotlInfo.getValidationCacheInfo().isResultExist());
			assertFalse(lotlInfo.getValidationCacheInfo().isError());
		}
		
	}
	
	private TLValidationJob getTLValidationJob() {
		tlValidationJob = new TLValidationJob();
		tlValidationJob.setOfflineDataLoader(offlineFileLoader);
		tlValidationJob.setOnlineDataLoader(onlineFileLoader);
		tlValidationJob.setCacheCleaner(cacheCleaner);
		tlValidationJob.setTrustedListSources(czSource);
		tlValidationJob.setTrustedListCertificateSource(new TrustedListsCertificateSource());
		tlValidationJob.offlineRefresh();
		return tlValidationJob;
	}
	
	private TLValidationJob getLOTLValidationJob() {
		tlValidationJob = new TLValidationJob();
		tlValidationJob.setOfflineDataLoader(offlineFileLoader);
		tlValidationJob.setOnlineDataLoader(onlineFileLoader);
		tlValidationJob.setCacheCleaner(cacheCleaner);
		tlValidationJob.setListOfTrustedListSources(lotlSource);
		tlValidationJob.offlineRefresh();
		return tlValidationJob;
	}
	
	private LOTLSource getPeruvianLotlSource() {
		LOTLSource peruvianLotlSource = new LOTLSource();
		peruvianLotlSource.setUrl("http://dss.nowina.lu/peru-lotl");
		CertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
		trustedCertificateSource.addCertificate(DSSUtils.loadCertificate(new File("src/test/resources/pe-signing-cert.cer")));
		peruvianLotlSource.setCertificateSource(trustedCertificateSource);
		return peruvianLotlSource;
	}
	
	private void updateTLUrl(String url) {
		urlMap.put(CZ_URL, new FileDocument(url));
	}
	
	private void updateLOTLUrl(String url) {
		urlMap.put(LOTL_URL, new FileDocument(url));
	}
	
	private void updatePivotUrl(String url) {
		CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
		trustedCertificateSource.addCertificate(pivotSigningCertificate);
		lotlSource.setCertificateSource(trustedCertificateSource);

		urlMap.put("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-247-mp.xml", 
				new FileDocument(url));
		updateLOTLUrl(url);
	}
	
	@AfterEach
	public void clean() throws IOException {
		File cacheDirectory = new File("target/cache");
		cacheDirectory.mkdirs();
		Files.walk(cacheDirectory.toPath()).map(Path::toFile).forEach(File::delete);
	}

}
