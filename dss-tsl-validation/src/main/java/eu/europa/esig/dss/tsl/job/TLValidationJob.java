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
package eu.europa.esig.dss.tsl.job;

import eu.europa.esig.dss.alert.Alert;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.tsl.alerts.TLValidationJobAlerter;
import eu.europa.esig.dss.tsl.cache.CacheCleaner;
import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.access.CacheAccessByKey;
import eu.europa.esig.dss.tsl.cache.access.CacheAccessFactory;
import eu.europa.esig.dss.tsl.cache.access.ReadOnlyCacheAccess;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.runnable.LOTLAnalysis;
import eu.europa.esig.dss.tsl.runnable.LOTLWithPivotsAnalysis;
import eu.europa.esig.dss.tsl.runnable.TLAnalysis;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.tsl.summary.ValidationJobSummaryBuilder;
import eu.europa.esig.dss.tsl.sync.AcceptAllStrategy;
import eu.europa.esig.dss.tsl.sync.SynchronizationStrategy;
import eu.europa.esig.dss.tsl.sync.TrustedListCertificateSourceSynchronizer;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

/**
 * The main class performing the TL/LOTL download / parsing / validation tasks
 *
 */
public class TLValidationJob {

	private static final Logger LOG = LoggerFactory.getLogger(TLValidationJob.class);

	/**
	 * Contains all caches for the current validation job
	 */
	private final CacheAccessFactory cacheAccessFactory = new CacheAccessFactory();

	/**
	 * Provides methods to manage the asynchronous behaviour
	 */
	private ExecutorService executorService = Executors.newCachedThreadPool();

	/**
	 * Array of zero, one or more Trusted List (TL) sources.
	 * 
	 * These trusted lists are not referenced in a List Of Trusted Lists (LOTL)
	 */
	private TLSource[] trustedListSources;

	/**
	 * Array of zero, one or more List Of Trusted List (LOTL) sources.
	 */
	private LOTLSource[] listOfTrustedListSources;
	
	/**
	 * The DSSFileLoader used for offline data loading from a local source
	 */
	private DSSFileLoader offlineLoader;

	/**
	 * The DSSFileLoader used for online data loading from a remote source
	 */
	private DSSFileLoader onlineLoader;
	
	/**
	 * Used to clean the cache
	 */
	private CacheCleaner cacheCleaner;

	/**
	 * The certificate source to be synchronized
	 */
	private TrustedListsCertificateSource trustedListCertificateSource;

	/**
	 * The strategy to follow to synchronize the certificates.
	 * 
	 * Default : all trusted lists and LOTLs are synchronized
	 */
	private SynchronizationStrategy synchronizationStrategy = new AcceptAllStrategy();

	/**
	 * This property allows to print the cache content before and after the
	 * synchronization (default : false)
	 */
	private boolean debug = false;
	
	/**
     * List of LOTL info alerts
     */
    private List<Alert<LOTLInfo>> lotlAlerts;
	
	/**
     * List of TL info alerts
     */
    private List<Alert<TLInfo>> tlAlerts;

	/**
	 * Default constructor instantiating object with null configuration
	 */
	public TLValidationJob() {
	}

	/**
	 * Sets the additional TL Sources
	 *
	 * @param trustedListSources {@link TLSource}s
	 */
	public void setTrustedListSources(TLSource... trustedListSources) {
		this.trustedListSources = trustedListSources;
	}

	/**
	 * Sets the LOTL Sources
	 *
	 * @param listOfTrustedListSources {@link LOTLSource}s
	 */
	public void setListOfTrustedListSources(LOTLSource... listOfTrustedListSources) {
		this.listOfTrustedListSources = listOfTrustedListSources;
	}

	/**
	 * Sets the execution service to manage the asynchronous behaviour
	 *
	 * @param executorService {@link ExecutorService}
	 */
	public void setExecutorService(ExecutorService executorService) {
		if (this.executorService != null && !this.executorService.isShutdown()) {
			this.executorService.shutdownNow();
		}
		this.executorService = executorService;
	}
	
	/**
	 * Sets the offline DSSFileLoader used for data loading from the local source
	 * @param offlineLoader {@link DSSFileLoader}
	 */
	public void setOfflineDataLoader(DSSFileLoader offlineLoader) {
		this.offlineLoader = offlineLoader;
	}

	/**
	 * Sets the online DSSFileLoader used for data loading from a remote source
	 * @param onlineLoader {@link DSSFileLoader}
	 */
	public void setOnlineDataLoader(DSSFileLoader onlineLoader) {
		this.onlineLoader = onlineLoader;
	}
	
	/**
	 * Sets the cacheCleaner
	 * @param cacheCleaner {@link CacheCleaner}
	 */
	public void setCacheCleaner(final CacheCleaner cacheCleaner) {
		this.cacheCleaner = cacheCleaner;
	}
	
	/**
	 * Sets the TrustedListsCertificateSource to be filled with the job
	 * 
	 * @param trustedListCertificateSource
	 *                                     the TrustedListsCertificateSource to fill
	 *                                     with the job results
	 */
	public void setTrustedListCertificateSource(TrustedListsCertificateSource trustedListCertificateSource) {
		this.trustedListCertificateSource = trustedListCertificateSource;
	}

	/**
	 * Sets the strategy to follow for the certificate synchronization
	 * 
	 * @param synchronizationStrategy
	 *                                the different options for the certificate
	 *                                synchronization
	 */
	public void setSynchronizationStrategy(SynchronizationStrategy synchronizationStrategy) {
		Objects.requireNonNull(synchronizationStrategy, "The SynchronizationStrategy cannot be null");
		this.synchronizationStrategy = synchronizationStrategy;
	}

	/**
	 * Sets the debug mode (print the cache contents before and after the
	 * synchronization)
	 * 
	 * @param debug
	 *              TRUE to enable the debug mode (default = false)
	 */
	public void setDebug(boolean debug) {
		this.debug = debug;
	}
	
	/**
	 * Sets the LOTL alerts to be processed
	 * 
	 * @param lotlAlerts a list of {@link Alert}s
	 */
	public void setLOTLAlerts(List<Alert<LOTLInfo>> lotlAlerts) {
	    this.lotlAlerts = lotlAlerts;
	}
	
	/**
	 * Sets the TL alerts to be processed
	 * 
	 * @param tlAlerts a list of {@link Alert}s
	 */
	public void setTLAlerts(List<Alert<TLInfo>> tlAlerts) {
	    this.tlAlerts = tlAlerts;
	}

	/**
	 * Returns validation job summary for all processed LOTL / TLs
	 * @return {@link TLValidationJobSummary}
	 */
	public synchronized TLValidationJobSummary getSummary() {
		return new ValidationJobSummaryBuilder(cacheAccessFactory.getReadOnlyCacheAccess(), trustedListSources, listOfTrustedListSources)
				.build();
	}

	/**
	 * Used to execute the refresh in offline mode (no date from remote sources will be downloaded)
	 * By default used on initialization
	 */
	public synchronized void offlineRefresh() {
		Objects.requireNonNull(offlineLoader, "The offlineLoader must be defined!");
		LOG.info("Offline refresh is running...");
		refresh(offlineLoader);
		LOG.info("Offline refresh is DONE.");
	}

	/**
	 * Used to execute the refresh in online mode (all data will be updated from remote sources)
	 * Used as default database update.
	 */
	public synchronized void onlineRefresh() {
		Objects.requireNonNull(onlineLoader, "The onlineLoader must be defined!");
		LOG.info("Online refresh is running...");
		refresh(onlineLoader);
		LOG.info("Online refresh is DONE.");
	}

	private void refresh(DSSFileLoader dssFileLoader) {

		List<TLSource> currentTLSources = new ArrayList<>();
		if (trustedListSources != null) {
			currentTLSources.addAll(Arrays.asList(trustedListSources));
		}

		// Execute all LOTLs
		if (Utils.isArrayNotEmpty(listOfTrustedListSources)) {
			final List<LOTLSource> lotlList = Arrays.asList(listOfTrustedListSources);

			executeLOTLSourcesAnalysis(lotlList, dssFileLoader);

			// Check LOTLs consistency

			// extract TLSources from cached LOTLs
			currentTLSources.addAll(extractTlSources(lotlList));
		}

		// And then, execute all TLs (manual configs + TLs from LOTLs)
		executeTLSourcesAnalysis(currentTLSources, dssFileLoader);

		// alerts()
		if (Utils.isCollectionNotEmpty(lotlAlerts) || Utils.isCollectionNotEmpty(tlAlerts)) {
			TLValidationJobSummary jobSummary = getSummary();
			TLValidationJobAlerter alerter = new TLValidationJobAlerter(lotlAlerts, tlAlerts);
			alerter.detectChanges(jobSummary);
		}

		if (debug) {
			LOG.info("Dump before synchronization");
			cacheAccessFactory.getDebugCacheAccess().dump();
		}

		// TLCerSource sync + cache sync if needed
		synchronizeTLCertificateSource();

		executeCacheCleaner();

		if (debug) {
			LOG.info("Dump after synchronization");
			cacheAccessFactory.getDebugCacheAccess().dump();
		}
	}

	private void executeLOTLSourcesAnalysis(List<LOTLSource> lotlSources, DSSFileLoader dssFileLoader) {
		checkNoDuplicateUrls(lotlSources);

		int nbLOTLSources = lotlSources.size();

		LOG.info("Running analysis for {} LOTLSource(s)", nbLOTLSources);

		Map<CacheKey, ParsingCacheDTO> oldParsingValues = extractParsingCache(lotlSources);

		CountDownLatch latch = new CountDownLatch(nbLOTLSources);
		for (LOTLSource lotlSource : lotlSources) {
			final CacheAccessByKey cacheAccess = cacheAccessFactory.getCacheAccess(lotlSource.getCacheKey());
			if (lotlSource.isPivotSupport()) {
				executorService.submit(new LOTLWithPivotsAnalysis(lotlSource, cacheAccess, dssFileLoader, cacheAccessFactory, latch));
			} else {
				executorService.submit(new LOTLAnalysis(lotlSource, cacheAccess, dssFileLoader, latch));
			}
		}

		try {
			latch.await();
			LOG.info("Analysis is DONE for {} LOTLSource(s)", nbLOTLSources);
		} catch (InterruptedException e) {
			LOG.error("Interruption in the LOTLSource process", e);
			Thread.currentThread().interrupt();
		}

		Map<CacheKey, ParsingCacheDTO> newParsingValues = extractParsingCache(lotlSources);

		// Analyze introduced changes for TLs + adapt cache for TLs (EXPIRED)
		final LOTLChangeApplier lotlChangeApplier = new LOTLChangeApplier(cacheAccessFactory.getTLChangesCacheAccess(), oldParsingValues, newParsingValues);
		lotlChangeApplier.analyzeAndApply();
	}
	
	private List<TLSource> extractTlSources(List<LOTLSource> lotlList) {
		TLSourceBuilder tlSourceBuilder = new TLSourceBuilder(lotlList, extractParsingCache(lotlList));
		return tlSourceBuilder.build();
	}
	
    private Map<CacheKey, ParsingCacheDTO> extractParsingCache(List<LOTLSource> lotlSources) {
        final ReadOnlyCacheAccess readOnlyCacheAccess = cacheAccessFactory.getReadOnlyCacheAccess();
        return lotlSources.stream().collect(Collectors.toMap(LOTLSource::getCacheKey, s -> readOnlyCacheAccess.getParsingCacheDTO(s.getCacheKey())));
    }

	private void executeTLSourcesAnalysis(List<TLSource> tlSources, DSSFileLoader dssFileLoader) {
		int nbTLSources = tlSources.size();
		if (nbTLSources == 0) {
			LOG.info("No TL to be analyzed");
			return;
		}

		checkNoDuplicateUrls(tlSources);

		LOG.info("Running analysis for {} TLSource(s)", nbTLSources);

		CountDownLatch latch = new CountDownLatch(nbTLSources);
		for (TLSource tlSource : tlSources) {
			final CacheAccessByKey cacheAccess = cacheAccessFactory.getCacheAccess(tlSource.getCacheKey());
			executorService.submit(new TLAnalysis(tlSource, cacheAccess, dssFileLoader, latch));
		}

		try {
			latch.await();
			LOG.info("Analysis is DONE for {} TLSource(s)", nbTLSources);
		} catch (InterruptedException e) {
			LOG.error("Interruption in the TLAnalysis process", e);
			Thread.currentThread().interrupt();
		}
	}

	private void synchronizeTLCertificateSource() {
		if (trustedListCertificateSource == null) {
			LOG.warn("No TrustedListCertificateSource to be synchronized");
			return;
		}

		TrustedListCertificateSourceSynchronizer synchronizer = new TrustedListCertificateSourceSynchronizer(trustedListSources, listOfTrustedListSources,
				trustedListCertificateSource, synchronizationStrategy, cacheAccessFactory.getSynchronizerCacheAccess());
		synchronizer.sync();
	}

	private void executeCacheCleaner() {
		if (cacheCleaner == null) {
			LOG.debug("Cache cleaner is not defined");
			return;
		}

		LOG.info("Running CacheCleaner");
		Set<CacheKey> cacheKeys = cacheAccessFactory.getReadOnlyCacheAccess().getAllCacheKeys();
		for (CacheKey cacheKey : cacheKeys) {
			final CacheAccessByKey cacheAccess = cacheAccessFactory.getCacheAccess(cacheKey);
			cacheCleaner.clean(cacheAccess);
		}
		LOG.info("CacheCleaner process is DONE");
	}

	/**
	 * Duplicate urls mean cache conflict.
	 * 
	 * @param sources
	 *                a list of TLSource
	 */
	private void checkNoDuplicateUrls(List<? extends TLSource> sources) {
		List<String> allUrls = sources.stream().map(TLSource::getUrl).collect(Collectors.toList());
		Set<String> uniqueUrls = new HashSet<>(allUrls);
		if (allUrls.size() > uniqueUrls.size()) {
			throw new DSSException(String.format("Duplicate urls found : %s", allUrls));
		}
	}

}
