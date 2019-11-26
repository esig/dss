package eu.europa.esig.dss.cookbook.example.snippets;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.alerts.LOTLAlert;
import eu.europa.esig.dss.tsl.alerts.TLAlert;
import eu.europa.esig.dss.tsl.alerts.detections.LOTLLocationChangeDetection;
import eu.europa.esig.dss.tsl.alerts.detections.OJUrlChangeDetection;
import eu.europa.esig.dss.tsl.alerts.detections.TLExpirationDetection;
import eu.europa.esig.dss.tsl.alerts.detections.TLSignatureErrorDetection;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogLOTLLocationChangeAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogOJUrlChangeAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTLExpirationAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTLSignatureErrorAlertHandler;
import eu.europa.esig.dss.tsl.cache.CacheCleaner;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.sync.AcceptAllStrategy;

public class EuropeanLOTLSnippets {
	
	private static Logger LOG = LoggerFactory.getLogger(EuropeanLOTLSnippets.class);

	// tag::complete-european-lotl-config[]

	// Should be externalized
	private static final String LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";
	private static final String OJ_URL = "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2019.276.01.0001.01.ENG";
	
	public TLValidationJob job() {
		TLValidationJob job = new TLValidationJob();
		job.setOfflineDataLoader(offlineLoader());
		job.setOnlineDataLoader(onlineLoader());
		job.setTrustedListCertificateSource(trustedCertificateSource());
		job.setSynchronizationStrategy(new AcceptAllStrategy());
		job.setCacheCleaner(cacheCleaner());

		LOTLSource europeanLOTL = europeanLOTL();
		job.setListOfTrustedListSources(europeanLOTL);

		job.setAlerts(Arrays.asList(tlSigningAlert(), tlExpirationDetection(), ojUrlAlert(europeanLOTL),
				lotlLocationAlert(europeanLOTL)));

		return job;
	}

	public TrustedListsCertificateSource trustedCertificateSource() {
		return new TrustedListsCertificateSource();
	}

	public LOTLSource europeanLOTL() {
		LOTLSource lotlSource = new LOTLSource();
		lotlSource.setUrl(LOTL_URL);
		lotlSource.setCertificateSource(officialJournalContentKeyStore());
		lotlSource.setSigningCertificatesAnnouncementPredicate(new OfficialJournalSchemeInformationURI(OJ_URL));
		lotlSource.setPivotSupport(true);
		return lotlSource;
	}

	public CertificateSource officialJournalContentKeyStore() {
		try {
			return new KeyStoreCertificateSource(new File("src/main/resources/keystore.p12"), "PKCS12", "dss-password");
		} catch (IOException e) {
			throw new DSSException("Unable to load the keystore", e);
		}
	}

	public DSSFileLoader offlineLoader() {
		FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader();
		offlineFileLoader.setCacheExpirationTime(Long.MAX_VALUE);
		offlineFileLoader.setDataLoader(new IgnoreDataLoader());
		offlineFileLoader.setFileCacheDirectory(tlCacheDirectory());
		return offlineFileLoader;
	}

	public DSSFileLoader onlineLoader() {
		FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader();
		offlineFileLoader.setCacheExpirationTime(0);
		offlineFileLoader.setDataLoader(dataLoader());
		offlineFileLoader.setFileCacheDirectory(tlCacheDirectory());
		return offlineFileLoader;
	}

	public File tlCacheDirectory() {
		File rootFolder = new File(System.getProperty("java.io.tmpdir"));
		File tslCache = new File(rootFolder, "dss-tsl-loader");
		if (tslCache.mkdirs()) {
			LOG.info("TL Cache folder : {}", tslCache.getAbsolutePath());
		}
		return tslCache;
	}

	public CommonsDataLoader dataLoader() {
		return new CommonsDataLoader();
	}

	public CacheCleaner cacheCleaner() {
		CacheCleaner cacheCleaner = new CacheCleaner();
		cacheCleaner.setCleanMemory(true);
		cacheCleaner.setCleanFileSystem(true);
		cacheCleaner.setDSSFileLoader(offlineLoader());
		return cacheCleaner;
	}

	// Optionally : alerting.
	// Recommended detections : OJUrlChangeDetection + LOTLLocationChangeDetection

	public TLAlert tlSigningAlert() {
		TLSignatureErrorDetection signingDetection = new TLSignatureErrorDetection();
		LogTLSignatureErrorAlertHandler handler = new LogTLSignatureErrorAlertHandler();
		return new TLAlert(signingDetection, handler);
	}

	public TLAlert tlExpirationDetection() {
		TLExpirationDetection expirationDetection = new TLExpirationDetection();
		LogTLExpirationAlertHandler handler = new LogTLExpirationAlertHandler();
		return new TLAlert(expirationDetection, handler);
	}

	public LOTLAlert ojUrlAlert(LOTLSource source) {
		OJUrlChangeDetection ojUrlDetection = new OJUrlChangeDetection(source);
		LogOJUrlChangeAlertHandler handler = new LogOJUrlChangeAlertHandler();
		return new LOTLAlert(ojUrlDetection, handler);
	}

	public LOTLAlert lotlLocationAlert(LOTLSource source) {
		LOTLLocationChangeDetection lotlLocationDetection = new LOTLLocationChangeDetection(source);
		LogLOTLLocationChangeAlertHandler handler = new LogLOTLLocationChangeAlertHandler();
		return new LOTLAlert(lotlLocationDetection, handler);
	}

	// end::complete-european-lotl-config[]

}
