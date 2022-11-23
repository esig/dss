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

import eu.europa.esig.dss.alert.handler.AlertHandler;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.tsl.DownloadInfoRecord;
import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.ParsingInfoRecord;
import eu.europa.esig.dss.spi.tsl.PivotInfo;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.tsl.ValidationInfoRecord;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.alerts.LOTLAlert;
import eu.europa.esig.dss.tsl.alerts.TLAlert;
import eu.europa.esig.dss.tsl.alerts.detections.LOTLLocationChangeDetection;
import eu.europa.esig.dss.tsl.alerts.detections.OJUrlChangeDetection;
import eu.europa.esig.dss.tsl.alerts.detections.TLSignatureErrorDetection;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTLSignatureErrorAlertHandler;
import eu.europa.esig.dss.tsl.cache.CacheCleaner;
import eu.europa.esig.dss.tsl.function.GrantedTrustService;
import eu.europa.esig.dss.tsl.function.NonEmptyTrustService;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.function.TLPredicateFactory;
import eu.europa.esig.dss.tsl.function.TrustServiceProviderByTSPName;
import eu.europa.esig.dss.tsl.function.TrustServiceProviderPredicate;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.tsl.sync.AcceptAllStrategy;
import eu.europa.esig.dss.tsl.sync.ExpirationAndSignatureCheckStrategy;
import eu.europa.esig.dss.tsl.sync.SynchronizationStrategy;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.trustedlist.jaxb.tsl.InternationalNamesType;
import eu.europa.esig.trustedlist.jaxb.tsl.MultiLangNormStringType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executors;

public class TLValidationJobSnippets {

	public void sample() throws IOException {

		// tag::multi-trusted-certificate-sources[]
		// import eu.europa.esig.dss.validation.CertificateVerifier;
		// import eu.europa.esig.dss.validation.CommonCertificateVerifier;

		CertificateVerifier cv = new CommonCertificateVerifier();
		cv.setTrustedCertSources(trustStoreSource(), trustedListSource());
		// end::multi-trusted-certificate-sources[]
	}

	public CertificateSource trustStoreSource() throws IOException {
		// tag::trust-store[]
		// import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
		// import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
		// import eu.europa.esig.dss.spi.DSSUtils;

		KeyStoreCertificateSource keystore = new KeyStoreCertificateSource(new File("src/main/resources/keystore.p12"), "PKCS12", getPassword());

		CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
		trustedCertificateSource.importAsTrusted(keystore);

		// Optionally, certificates can also be directly added
		trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIC9TCCAd2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADArMQswCQYDVQQGEwJBQTEMMAoGA1UEChMDRFNTMQ4wDAYDVQQDEwVJQ0EgQTAeFw0xMzEyMDIxNzMzMTBaFw0xNTEyMDIxNzMzMTBaMDAxCzAJBgNVBAYTAkFBMQwwCgYDVQQKEwNEU1MxEzARBgNVBAMTCnVzZXIgQSBSU0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJUHHAphmSDdQ1t62tppK+dLTANsE2nAj+HCpasS3ohlBsrhteRsvTAbrDyIzCmTYWu/nVI4TGvbzBESwV/QitlkoMLpYFw32MIBf2DLmECzGJ3vm5haw6u8S9quR1h8Vu7QWd+5KMabZuR+j91RiSuoY0xS2ZQxJw1vhvW9hRYjAgMBAAGjgaIwgZ8wCQYDVR0TBAIwADAdBgNVHQ4EFgQU9ESnTWfwg13c3LQZzqqwibY5WVYwUwYDVR0jBEwwSoAUIO1CDsBSUcEoFZxKaWf1PAL1U+uhL6QtMCsxDDAKBgNVBAoTA0RTUzELMAkGA1UEBhMCQUExDjAMBgNVBAMTBVJDQSBBggEBMAsGA1UdDwQEAwIHgDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEFBQADggEBAGnhhnoyVUhDnr/BSbZ/uWfSuwzFPG+2V9K6WxdIaaXOORFGIdFwGlAwA/Qzpq9snfBxuTkAykxq0uEDhHTj0qXxWRjQ+Dop/DrmccoF/zDvgGusyY1YXaABd/kc3IYt7ns7z3tpiqIz4A7a/UHplBRXfqjyaZurZuJQRaSdxh6CNhdEUiUBxkbb1SdMjuOgjzSDjcDjcegjvDquMKdDetvtu2Qh4ConBBo3fUImwiFRWnbudS5H2HE18ikC7gY/QIuNr7USf1PNyUgcG2g31cMtemj7UTBHZ2V/jPf7ZXqwfnVSaYkNvM3weAI6R3PI0STjdxN6a9qjt9xld40YEdw="));
		// end::trust-store[]

		return trustedCertificateSource;
	}

	public CertificateSource trustedListSource() {
		// tag::trusted-list-source[]
		// import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;

		TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();
		// end::trusted-list-source[]
		return trustedListsCertificateSource;
	}

	private String getPassword() {
		return "dss-password";
	}

	public void jobConfig() {
		// tag::job-config-sources[]
		// import eu.europa.esig.dss.tsl.job.TLValidationJob;

		TLValidationJob validationJob = new TLValidationJob();
		// Specify where the TL/LOTL is hosted and which are the signing certificate(s) for these TL/LOTL.
		validationJob.setTrustedListSources(boliviaTLSource(), costaRicaTLSource());
		validationJob.setListOfTrustedListSources(europeanLOTLSource(), unitedStatesLOTLSource());
		// end::job-config-sources[]
	}

	public void refresh() {
		// tag::refresh[]
		// import eu.europa.esig.dss.tsl.job.TLValidationJob;

		TLValidationJob validationJob = new TLValidationJob();

		// tag::offline-refresh[]
		// call with the Offline Loader (application initialization)
		validationJob.offlineRefresh();
		// end::offline-refresh[]

		// call with the Online Loader (callable every day/hour in a cron)
		validationJob.onlineRefresh();

		// end::refresh[]
	}

	// tag::job-loaders[]
	// import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
	// import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
	// import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;

	public DSSFileLoader offlineLoader() {
		FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader();
		offlineFileLoader.setCacheExpirationTime(-1); // negative value means cache never expires
		offlineFileLoader.setDataLoader(new IgnoreDataLoader()); // do not download from Internet
		offlineFileLoader.setFileCacheDirectory(tlCacheDirectory());
		return offlineFileLoader;
	}

	public DSSFileLoader onlineLoader() {
		FileCacheDataLoader onlineFileLoader = new FileCacheDataLoader();
		onlineFileLoader.setCacheExpirationTime(0);
		onlineFileLoader.setDataLoader(dataLoader()); // instance of DataLoader which can access to Internet (proxy,...)
		onlineFileLoader.setFileCacheDirectory(tlCacheDirectory());
		return onlineFileLoader;
	}
	// end::job-loaders[]

	public void synchronizationStrategyConfiguration() {
		// tag::synchronization-strategy[]
		// import eu.europa.esig.dss.tsl.job.TLValidationJob;
		// import eu.europa.esig.dss.tsl.sync.AcceptAllStrategy;
		// import eu.europa.esig.dss.tsl.sync.ExpirationAndSignatureCheckStrategy;

		TLValidationJob tlValidationJob = new TLValidationJob();

		// AcceptAllStrategy will accept all Trusted Lists, despite its signature validation status (used by default)
		tlValidationJob.setSynchronizationStrategy(new AcceptAllStrategy());

		// ExpirationAndSignatureCheckStrategy allow configuring acceptance of various checks to be performed on Trusted Lists
		ExpirationAndSignatureCheckStrategy checkStrategy = new ExpirationAndSignatureCheckStrategy();
		// This check configures whether expired LOTLs shall be accepted, otherwise they will be skipped (FALSE by default)
		checkStrategy.setAcceptExpiredListOfTrustedLists(false);
		// This check configures whether expired TLs shall be accepted, otherwise they will be skipped (FALSE by default)
		checkStrategy.setAcceptExpiredTrustedList(false);
		// This check configures whether LOTLs with invalid signatures shall be accepted, otherwise they will be skipped (FALSE by default)
		checkStrategy.setAcceptInvalidListOfTrustedLists(false);
		// This check configures whether TLs with invalid signatures shall be accepted, otherwise they will be skipped (FALSE by default)
		checkStrategy.setAcceptInvalidTrustedList(false);
		// Provide the configured strategy to the TLValidationJob
		tlValidationJob.setSynchronizationStrategy(checkStrategy);
		// end::synchronization-strategy[]
	}

	public void allValidTrustedListsStrategy() {
		TLValidationJob tlValidationJob = new TLValidationJob();

		// tag::custom-strategy[]
		// import eu.europa.esig.dss.tsl.sync.SynchronizationStrategy;
		// import eu.europa.esig.dss.spi.tsl.TLInfo;
		// import eu.europa.esig.dss.spi.tsl.LOTLInfo;

		// Create a custom strategy by implementing the interface
		// This strategy will accept only LOTL/TLs with valid signatures
		SynchronizationStrategy customStrategy = new SynchronizationStrategy() {

			@Override
			public boolean canBeSynchronized(TLInfo trustedList) {
				return trustedList.getValidationCacheInfo().isValid();
			}

			@Override
			public boolean canBeSynchronized(LOTLInfo listOfTrustedList) {
				return listOfTrustedList.getValidationCacheInfo().isValid();
			}

		};

		// Provide the strategy to the TLValidationJob
		tlValidationJob.setSynchronizationStrategy(customStrategy);
		// end::custom-strategy[]

	}

	public void trustServiceProviderPredicate() {
		// tag::trust-service-provider-predicate[]
		// import eu.europa.esig.dss.tsl.source.TLSource;
		// import eu.europa.esig.dss.tsl.function.NonEmptyTrustService;
		// import eu.europa.esig.dss.tsl.function.TrustServiceProviderByTSPName;

		TLSource tlSource = new TLSource();
		// This predicate will accept only TrustServiceProviders with TSPName "LuxTrust S.A."
		tlSource.setTrustServiceProviderPredicate(new TrustServiceProviderByTSPName("LuxTrust S.A."));
		// This predicate will accept all TrustServiceProviders which have at least one TSPService
		tlSource.setTrustServiceProviderPredicate(new NonEmptyTrustService());
		// It is also possible to create combined predicates. For example, this predicate will accept
		// TrustServiceProviders with one of "LuxTrust S.A." or "Cryptolog International" names
		tlSource.setTrustServiceProviderPredicate(new TrustServiceProviderByTSPName("LuxTrust S.A.").or
				(new TrustServiceProviderByTSPName("Cryptolog International")));
		// end::trust-service-provider-predicate[]
	}

	public void trustServicePredicate() {
		// tag::trust-service-predicate[]
		// import eu.europa.esig.dss.tsl.source.TLSource;
		// import eu.europa.esig.dss.tsl.function.GrantedTrustService;

		TLSource tlSource = new TLSource();
		// This predicate filters Trusted Services which has an acceptable (e.g. accredited or granted) status
		tlSource.setTrustServicePredicate(new GrantedTrustService());
		// end::trust-service-predicate[]
	}

	public CacheCleaner cacheCleaner() {
		// tag::cache-cleaner[]
		// import eu.europa.esig.dss.tsl.cache.CacheCleaner;

		// Create CacheCleaner
		CacheCleaner cacheCleaner = new CacheCleaner();
		// free the space in memory
		cacheCleaner.setCleanMemory(true);
		// remove the stored file(s) on the file-system
		cacheCleaner.setCleanFileSystem(true);
		// if the file-system cleaner is enabled, inject the configured loader from the
		// online or offline refresh data loader.
		cacheCleaner.setDSSFileLoader(offlineLoader());
		// end::cache-cleaner[]

		return cacheCleaner;
	}

	public void alerting() {
		// tag::alerting[]
		// import eu.europa.esig.dss.tsl.job.TLValidationJob;
		// import eu.europa.esig.dss.tsl.alerts.detections.TLSignatureErrorDetection;
		// import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTLSignatureErrorAlertHandler;
		// import eu.europa.esig.dss.tsl.alerts.TLAlert;
		// import eu.europa.esig.dss.alert.handler.AlertHandler;
		// import eu.europa.esig.dss.spi.tsl.LOTLInfo;
		// import eu.europa.esig.dss.tsl.alerts.LOTLAlert;
		// import eu.europa.esig.dss.tsl.alerts.detections.LOTLLocationChangeDetection;

		TLValidationJob job = new TLValidationJob();
		// configure

		// Add a log message in case of invalid signatures
		TLAlert tlBrokenSignatureAlert = new TLAlert(new TLSignatureErrorDetection(), new LogTLSignatureErrorAlertHandler());

		// Send an email in case of new Official Journal detected
		AlertHandler<LOTLInfo> mailSender = new AlertHandler<LOTLInfo>() {

			@Override
			public void process(LOTLInfo currentInfo) {
				String newOJUrl = currentInfo.getParsingCacheInfo().getSigningCertificateAnnouncementUrl();
				// code to send an email
				SampleUtils.sendEmail(newOJUrl);
			}

		};

		// The europeanLOTLSource is configured with an
		// OfficialJournalSchemeInformationURI
		LOTLAlert officialJournalDesynchronizationAlert = new LOTLAlert(new OJUrlChangeDetection(europeanLOTLSource()), mailSender);

		// Update a database in case of LOTL location change
		AlertHandler<LOTLInfo> databaseUpgrader = new AlertHandler<LOTLInfo>() {

			@Override
			public void process(LOTLInfo currentInfo) {
				String newLOTLUrl = null;

				String currentLOTLUrl = currentInfo.getUrl();
				List<PivotInfo> pivots = currentInfo.getPivotInfos();
				for (PivotInfo pivot : pivots) {
					if (!Utils.areStringsEqual(currentLOTLUrl, pivot.getLOTLLocation())) {
						newLOTLUrl = pivot.getLOTLLocation();
						break;
					}
				}

				// code to update a database
				SampleUtils.updateDatabase(newLOTLUrl);
			}

		};
		LOTLAlert lotlLocationChangeAlert = new LOTLAlert(new LOTLLocationChangeDetection(europeanLOTLSource()), databaseUpgrader);

		// add all alerts on the job
		job.setLOTLAlerts(Arrays.asList(officialJournalDesynchronizationAlert, lotlLocationChangeAlert));
		job.setTLAlerts(Arrays.asList(tlBrokenSignatureAlert));

		// end::alerting[]
	}

	public void predicates() {
		// tag::predicates[]
		// import eu.europa.esig.dss.tsl.source.LOTLSource;
		// import eu.europa.esig.dss.tsl.function.EULOTLOtherTSLPointer;
		// import eu.europa.esig.dss.tsl.function.XMLOtherTSLPointer;
		// import eu.europa.esig.dss.tsl.function.SchemeTerritoryOtherTSLPointer;

		LOTLSource lotlSource = new LOTLSource();
		// the predicates filter TSL pointers to XML documents with
		// "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists" type
		lotlSource.setLotlPredicate(TLPredicateFactory.createEULOTLPredicate());

		// the predicates filter only TSL pointers with scheme territories "DE" (Germany) and "RO" (Romania)
		// to XML documents with "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric" type
		// tag::predicate-country[]
		lotlSource.setTlPredicate(TLPredicateFactory.createEUTLCountryCodePredicate("DE", "RO"));
		// end::predicate-country[]
		// end::predicates[]
	}

	private void executorService() {
		// tag::executor-service[]
		// import eu.europa.esig.dss.tsl.job.TLValidationJob;
		// import java.util.concurrent.Executors;

		TLValidationJob tlValidationJob = new TLValidationJob();
		// Allows configuration of the execution process
		// Default : Executors.newCachedThreadPool() is used
		tlValidationJob.setExecutorService(Executors.newSingleThreadExecutor());
		// end::executor-service[]
	}

	private DataLoader dataLoader() {
		return new CommonsDataLoader();
	}

	private File tlCacheDirectory() {
		return null;
	}

	public TLSource frenchTLSource() {
		// tag::french-tl-source[]
		// import eu.europa.esig.dss.tsl.job.TLValidationJob;
		// import eu.europa.esig.dss.tsl.source.TLSource;
		// import eu.europa.esig.dss.tsl.function.GrantedTrustService;

		TLValidationJob tlValidationJob = new TLValidationJob();
		TLSource tlSource = new TLSource();

		// Mandatory : The url where the TL needs to be downloaded
		tlSource.setUrl("http://www.ssi.gouv.fr/eidas/TL-FR.xml");

		// A certificate source which contains the signing certificate(s) for the
		// current trusted list
		tlSource.setCertificateSource(getSigningCertificatesForFrenchTL());

		// Optional : predicate to filter trust services which are/were granted or
		// equivalent (pre/post eIDAS).
		// Input : implementation of TrustServicePredicate interface.
		// Default : none (select all)
		tlSource.setTrustServicePredicate(new GrantedTrustService());

		// Optional : predicate to filter the trust service providers
		// Input : implementation of TrustServiceProviderPredicate interface.
		// Default : none (select all)
		tlSource.setTrustServiceProviderPredicate(new CryptologOnlyTrustServiceProvider());

		//instance of CertificateSource where all trusted certificates and their properties (service type,...) are stored.
		tlValidationJob.setTrustedListSources(tlSource);
		// end::french-tl-source[]

		return tlSource;
	}

	public void summary() {
		// tag::tl-summary[]
		// import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
		// import eu.europa.esig.dss.tsl.job.TLValidationJob;
		// import eu.europa.esig.dss.spi.tsl.TLValidationJobSummary;
		// import eu.europa.esig.dss.spi.tsl.LOTLInfo;
		// import eu.europa.esig.dss.spi.tsl.DownloadInfoRecord;
		// import eu.europa.esig.dss.spi.tsl.ParsingInfoRecord;
		// import eu.europa.esig.dss.spi.tsl.ValidationInfoRecord;
		// import eu.europa.esig.dss.spi.tsl.TLInfo;
		// import java.util.List;

		TrustedListsCertificateSource trustedListCertificateSource = new TrustedListsCertificateSource();

		TLValidationJob job = new TLValidationJob();
		job.setTrustedListCertificateSource(trustedListCertificateSource);

		// ... config & refresh ...

		// A cache content summary can be computed on request
		TLValidationJobSummary summary = job.getSummary();

		// All information about processed LOTLSources
		List<LOTLInfo> lotlInfos = summary.getLOTLInfos();
		LOTLInfo lotlInfo = lotlInfos.get(0);
		// All data about the download (last occurrence, cache status, error,...)
		DownloadInfoRecord downloadCacheInfo = lotlInfo.getDownloadCacheInfo();

		// All data about the parsing (date, extracted data, cache status,...)
		ParsingInfoRecord parsingCacheInfo = lotlInfo.getParsingCacheInfo();

		// All data about the signature validation (signing certificate, validation
		// result, cache status,...)
		ValidationInfoRecord validationCacheInfo = lotlInfo.getValidationCacheInfo();

		// All information about processed TLSources (which are not linked to a
		// LOTLSource)
		List<TLInfo> otherTLInfos = summary.getOtherTLInfos();

		// or the last update can be collected from the TrustedListsCertificateSource
		TLValidationJobSummary lastSynchronizedSummary = trustedListCertificateSource.getSummary();

		// end::tl-summary[]

		downloadCacheInfo.getLastStateTransitionTime();
		parsingCacheInfo.getLastStateTransitionTime();
		validationCacheInfo.getLastStateTransitionTime();
		lastSynchronizedSummary.getLOTLInfos();

	}

	private TLSource costaRicaTLSource() {
		return null;
	}

	private TLSource boliviaTLSource() {
		return null;
	}

	private LOTLSource unitedStatesLOTLSource() {
		return null;
	}

	public LOTLSource europeanLOTLSource() {
		// tag::european-lotl-source[]
		// import eu.europa.esig.dss.tsl.job.TLValidationJob;
		// import eu.europa.esig.dss.tsl.source.LOTLSource;
		// import eu.europa.esig.dss.tsl.function.EULOTLOtherTSLPointer;
		// import eu.europa.esig.dss.tsl.function.EUTLOtherTSLPointer;
		// import eu.europa.esig.dss.tsl.function.XMLOtherTSLPointer;
		// import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
		// import eu.europa.esig.dss.tsl.function.GrantedTrustService;

		TLValidationJob tlValidationJob = new TLValidationJob();
		LOTLSource lotlSource = new LOTLSource();

		// Mandatory : The url where the LOTL needs to be downloaded
		lotlSource.setUrl("https://ec.europa.eu/tools/lotl/eu-lotl.xml");

		// A certificate source which contains the signing certificate(s) for the
		// current list of trusted lists
		lotlSource.setCertificateSource(getSigningCertificatesForEuropeanLOTL());

		// true or false for the pivot support. Default = false
		// More information :
		// https://ec.europa.eu/tools/lotl/pivot-lotl-explanation.html
		lotlSource.setPivotSupport(true);

		// Optional : the predicate which allows to find the LOTL definition in the LOTL
		// Input : implementation of Predicate<OtherTSLPointerType> interface (e.g. OtherTSLPointerPredicate)
		// Default : European configuration
		// Hint : Use TLPredicateFactory for a list of default configurations
		lotlSource.setLotlPredicate(TLPredicateFactory.createEULOTLPredicate());

		// Optional : the predicate which allows to find and/or filter the TL
		// definitions in the LOTL
		// Input : implementation of Predicate<OtherTSLPointerType> interface (e.g. OtherTSLPointerPredicate)
		// Default : all found trusted lists in the European LOTL
		// Hint : Use TLPredicateFactory for a list of default configurations
		lotlSource.setTlPredicate(TLPredicateFactory.createEUTLPredicate());

		// Optional : a predicate which allows to find back the signing certificates for
		// the current LOTL
		// Input : implementation of LOTLSigningCertificatesAnnouncementSchemeInformationURI interface.
		// Default : not defined
		//
		// OfficialJournalSchemeInformationURI allows to specify the Official Journal
		// URL where the signing certificates are published
		lotlSource.setSigningCertificatesAnnouncementPredicate(
				new OfficialJournalSchemeInformationURI("https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2019.276.01.0001.01.ENG"));

		// Optional : predicate to filter trust services which are/were granted or
		// equivalent (pre/post eIDAS). This parameter is applied on the related trusted
		// lists
		// Input : implementation of TrustServicePredicate interface.
		// Default : none (select all)
		lotlSource.setTrustServicePredicate(new GrantedTrustService());

		// Optional : predicate to filter the trust service providers. This parameter is
		// applied on the related trusted lists
		// Input : implementation of TrustServiceProviderPredicate interface.
		// Default : none (select all)
		lotlSource.setTrustServiceProviderPredicate(new CryptologOnlyTrustServiceProvider());

		tlValidationJob.setListOfTrustedListSources(lotlSource);
		// end::european-lotl-source[]

		return lotlSource;
	}

	private CertificateSource getSigningCertificatesForEuropeanLOTL() {
		try {
			return new KeyStoreCertificateSource(new File("src/main/resources/keystore.p12"), "PKCS12", "dss-password");
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private CertificateSource getSigningCertificatesForFrenchTL() {
		CertificateSource cs = new CommonCertificateSource();
		cs.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIFWjCCBEKgAwIBAgISESH4uNBzewNTch8/fZTnHRxBMA0GCSqGSIb3DQEBCwUAMIGXMQswCQYDVQQGEwJGUjEwMC4GA1UECgwnQWdlbmNlIE5hdGlvbmFsZSBkZXMgVGl0cmVzIFPDqWN1cmlzw6lzMRcwFQYDVQQLDA4wMDAyIDEzMDAwMzI2MjExMC8GA1UEAwwoQXV0b3JpdMOpIGRlIENlcnRpZmljYXRpb24gUGVyc29ubmVzIEFBRTEKMAgGA1UEBRMBMzAeFw0xOTA5MDkxMTEyMzdaFw0yMjA5MDkxMTEyMzdaMHwxCzAJBgNVBAYTAkZSMQ0wCwYDVQQKDARBTlRTMRcwFQYDVQQLDA4wMDAyIDEzMDAwNzY2OTEjMCEGA1UEAwwaTWF0aGlldSBKT1JSWSAzMzEwMDAzODk4am0xEDAOBgNVBCoMB01hdGhpZXUxDjAMBgNVBAQMBUpPUlJZMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4iGy9/ATBcm6vIHI0vHgDfvkdaE2QicBcJFyRjexawI8fudrX5ffiMJZV5GCFBERvlu2IwctE0kVWpHGu0QMyLTNl4ZGDhjmgpX0u5zrF0KzKafKVzrKFbo4wr9+ZkUiJChHOWqejVDq40dVbRN5RzAFacIL2A6wyywmreAMnloh+vG2BEgTcj1lWWKc5rJx+ISYvG5j1bmbFYgNnI6RfbbM9QD7g1Bxw91kCPilT1P1L37Ay4kQQhLVDYFEsxBcSRkginO1iFFUlMendzj4RlxEcFwrGj26fIkLOmSOfAzWjkHvCcxgXydc6Y8zNpe1bYFIiNdsyFrK+GwzH26v0wIDAQABo4IBuDCCAbQwCQYDVR0TBAIwADAYBgNVHSAEETAPMA0GCyqBegGBSAMBAgMBMEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuYW50cy5nb3V2LmZyL2FudHNhdjMvYWNfcGVyc29ubmVzX2FhZV8zLmNybDCBlAYIKwYBBQUHAQEEgYcwgYQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3NwLmFudHMuZ291di5mci9hbnRzYXYzL2FjX3BlcnNvbm5lc19hYWVfMzBBBggrBgEFBQcwAoY1aHR0cDovL3NwLmFudHMuZ291di5mci9hbnRzYXYzL2FjX3BlcnNvbm5lc19hYWVfMy5jZXIwDgYDVR0PAQH/BAQDAgZAMDcGCCsGAQUFBwEDBCswKTAIBgYEAI5GAQEwCAYGBACORgEEMBMGBgQAjkYBBjAJBgcEAI5GAQYBMCQGA1UdEQQdMBuBGW1hdGhpZXUuam9ycnlAc3NpLmdvdXYuZnIwHQYDVR0OBBYEFLGJXUMMaUx1wr2cJA7YxWipXF69MB8GA1UdIwQYMBaAFPVSfQ6yaX5wCwQ3h9ZQDSanC6SDMA0GCSqGSIb3DQEBCwUAA4IBAQCZidW3Bisie+Kf/NajL09gzeYhe0528GD//7z7RlMsMtEK3rCxW+El5lv37Zpi7WTZQN4qboP0K34y3QIzMt2BwUrGhP/u3ZBY/uuxXTD4p6DGZlbwrgnWNjAri2hS7J4T7n3LES/ieNDnj+EMa/d44wUMBQOayNnmDRneEwITljNnBTO1K0hkZwAdGx/5eH8dYEisNyjYAC+hSApN9sZqopU5Mb7Dautv6dqbRJQ2q/BuNqGPKKJKFtgpaVV9pFdetUVnAf/uBqGQ5iDWNCRyXnZ3gW7z747koSvNN2K/jWjA6u1c/cPgiUOBD3I9Ss0An8zcy5nsd+JJhTkOR8zG"));
		return cs;
	}

	// tag::trust-service-provider-custom-predicate[]
	// import eu.europa.esig.dss.tsl.function.TrustServiceProviderPredicate;
	// import eu.europa.esig.dss.utils.Utils;
	// import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;
	// import eu.europa.esig.trustedlist.jaxb.tsl.TSPInformationType;
	// import eu.europa.esig.trustedlist.jaxb.tsl.InternationalNamesType;
	// import eu.europa.esig.trustedlist.jaxb.tsl.MultiLangNormStringType;

	private static class CryptologOnlyTrustServiceProvider implements TrustServiceProviderPredicate {

		@Override
		public boolean test(TSPType t) {

			TSPInformationType tspInformation = t.getTSPInformation();
			if (tspInformation != null) {
				InternationalNamesType tspName = tspInformation.getTSPName();
				if (tspName != null && Utils.isCollectionNotEmpty(tspName.getName())) {
					for (MultiLangNormStringType langAndValue : tspName.getName()) {
						if ("Cryptolog International".equals(langAndValue.getValue())) {
							return true;
						}
					}
				}
			}
			return false;
		}

	}
	// end::trust-service-provider-custom-predicate[]

	private static class SampleUtils {

		private SampleUtils() {
		}

		public static void updateDatabase(String newLOTLUrl) {
			// nothing
		}

		public static void sendEmail(String newOJUrl) {
			// nothing
		}

	}
}
