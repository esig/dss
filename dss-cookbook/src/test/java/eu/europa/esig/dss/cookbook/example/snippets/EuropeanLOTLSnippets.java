/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
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
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

public class EuropeanLOTLSnippets {
	
	private static Logger LOG = LoggerFactory.getLogger(EuropeanLOTLSnippets.class);

	// tag::complete-european-lotl-config[]
	// import eu.europa.esig.dss.model.DSSException;
	// import eu.europa.esig.dss.model.FileDocument;
	// import eu.europa.esig.dss.service.crl.OnlineCRLSource;
	// import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
	// import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
	// import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
	// import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
	// import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
	// import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
	// import eu.europa.esig.dss.spi.x509.CertificateSource;
	// import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
	// import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
	// import eu.europa.esig.dss.tsl.alerts.LOTLAlert;
	// import eu.europa.esig.dss.tsl.alerts.TLAlert;
	// import eu.europa.esig.dss.tsl.alerts.detections.LOTLLocationChangeDetection;
	// import eu.europa.esig.dss.tsl.alerts.detections.OJUrlChangeDetection;
	// import eu.europa.esig.dss.tsl.alerts.detections.TLExpirationDetection;
	// import eu.europa.esig.dss.tsl.alerts.detections.TLSignatureErrorDetection;
	// import eu.europa.esig.dss.tsl.alerts.handlers.log.LogLOTLLocationChangeAlertHandler;
	// import eu.europa.esig.dss.tsl.alerts.handlers.log.LogOJUrlChangeAlertHandler;
	// import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTLExpirationAlertHandler;
	// import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTLSignatureErrorAlertHandler;
	// import eu.europa.esig.dss.tsl.cache.CacheCleaner;
	// import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
	// import eu.europa.esig.dss.tsl.job.TLValidationJob;
	// import eu.europa.esig.dss.tsl.source.LOTLSource;
	// import eu.europa.esig.dss.tsl.sync.AcceptAllStrategy;
	// import eu.europa.esig.dss.validation.CommonCertificateVerifier;
	// import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
	// import eu.europa.esig.dss.validation.SignedDocumentValidator;
	// import java.io.File;
	// import java.io.IOException;
	// import java.util.Arrays;

	// Should be externalized
	private static final String LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";
	private static final String OJ_URL = "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2019.276.01.0001.01.ENG";
	
	@Test
	public void test() {
		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		TLValidationJob job = job();
		TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();
		job.setTrustedListCertificateSource(trustedListsCertificateSource);
		job.onlineRefresh();
		commonCertificateVerifier.setTrustedCertSources(trustedListsCertificateSource);
		commonCertificateVerifier.setCrlSource(new OnlineCRLSource());
		commonCertificateVerifier.setOcspSource(new OnlineOCSPSource());
		commonCertificateVerifier.setAIASource(new DefaultAIASource());
		
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(
				new FileDocument("src/test/resources/signature-pool/signedXmlXadesB.xml"));
		validator.setCertificateVerifier(commonCertificateVerifier);
		
		validator.validateDocument();
	}
	
	public TLValidationJob job() {
		TLValidationJob job = new TLValidationJob();
		job.setOfflineDataLoader(offlineLoader());
		job.setOnlineDataLoader(onlineLoader());
		job.setTrustedListCertificateSource(trustedCertificateSource());
		job.setSynchronizationStrategy(new AcceptAllStrategy());
		job.setCacheCleaner(cacheCleaner());

		LOTLSource europeanLOTL = europeanLOTL();
		job.setListOfTrustedListSources(europeanLOTL);

		job.setLOTLAlerts(Arrays.asList(ojUrlAlert(europeanLOTL), lotlLocationAlert(europeanLOTL)));
		job.setTLAlerts(Arrays.asList(tlSigningAlert(), tlExpirationDetection()));

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
		offlineFileLoader.setCacheExpirationTime(-1); // negative value means cache never expires
		offlineFileLoader.setDataLoader(new IgnoreDataLoader());
		offlineFileLoader.setFileCacheDirectory(tlCacheDirectory());
		return offlineFileLoader;
	}

	public DSSFileLoader onlineLoader() {
		FileCacheDataLoader onlineFileLoader = new FileCacheDataLoader();
		onlineFileLoader.setCacheExpirationTime(0);
		onlineFileLoader.setDataLoader(dataLoader());
		onlineFileLoader.setFileCacheDirectory(tlCacheDirectory());
		return onlineFileLoader;
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

	public CommonsDataLoader dataLoaderWithTLSv3() {
		// tag::data-loader-tls-v3[]
		CommonsDataLoader dataLoader = new CommonsDataLoader();
		// enforce TLSv1.3 as a default SSL protocol
		dataLoader.setSslProtocol("TLSv1.3");
		// add supported SSL protocols (to be used by the server you establish connection with)
		dataLoader.setSupportedSSLProtocols(new String[] { "TLSv1.2", "TLSv1.3" });
		// end::data-loader-tls-v3[]
		return dataLoader;
	}

}
