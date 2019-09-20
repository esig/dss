package eu.europa.esig.dss.tsl.job;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.service.http.commons.DSSFileLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.tsl.cache.DownloadCache;
import eu.europa.esig.dss.tsl.cache.ParsingCache;
import eu.europa.esig.dss.tsl.cache.TLAnalysisCacheAccess;
import eu.europa.esig.dss.tsl.cache.ValidationCache;
import eu.europa.esig.dss.tsl.runnable.TLAnalysis;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;

public class TLValidationJob {

	private static final Logger LOG = LoggerFactory.getLogger(TLValidationJob.class);

	private ExecutorService executorService = Executors.newCachedThreadPool();

	private DownloadCache downloadCache = new DownloadCache();

	private ParsingCache parsingCache = new ParsingCache();

	private ValidationCache validationCache = new ValidationCache();

	/**
	 * Configured DataLoader to retrieve online data (usually an instance of the
	 * {@link CommonDaLoader} with the proxy,... configuration
	 */
	private DataLoader onlineDataLoader;

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
	 * File cache directory where the cache will be stored
	 */
	private File fileCacheDirectory;

	public void setOnlineDataLoader(DataLoader onlineDataLoader) {
		this.onlineDataLoader = onlineDataLoader;
	}

	public void setTrustedListSources(TLSource... trustedListSources) {
		this.trustedListSources = trustedListSources;
	}

	public void setListOfTrustedListSources(LOTLSource... listOfTrustedListSources) {
		this.listOfTrustedListSources = listOfTrustedListSources;
	}
	
	public void setFileCacheDirectory(File fileCacheDirectory) {
		this.fileCacheDirectory = fileCacheDirectory;
	}

	public void setExecutorService(ExecutorService executorService) {
		if (this.executorService != null && !this.executorService.isShutdown()) {
			this.executorService.shutdownNow();
		}
		this.executorService = executorService;
	}

	public void offlineRefresh() {
		FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader();
		if (fileCacheDirectory != null) {
			fileCacheDataLoader.setFileCacheDirectory(fileCacheDirectory);
		}
		fileCacheDataLoader.setCacheExpirationTime(Long.MAX_VALUE);
		fileCacheDataLoader.setDataLoader(new IgnoreDataLoader());
		refresh(fileCacheDataLoader);
	}

	public void onlineRefresh() {
		FileCacheDataLoader fileDataLoaderNoCache = new FileCacheDataLoader();
		if (fileCacheDirectory != null) {
			fileDataLoaderNoCache.setFileCacheDirectory(fileCacheDirectory);
		}
		fileDataLoaderNoCache.setCacheExpirationTime(0);
		fileDataLoaderNoCache.setDataLoader(onlineDataLoader);
		refresh(fileDataLoaderNoCache);
	}

	private void refresh(DSSFileLoader dssFileLoader) {

		List<TLSource> currentTLSources = new ArrayList<TLSource>();
		if (trustedListSources != null) {
			currentTLSources = Arrays.asList(trustedListSources);
		}

		// Execute all LOTLs
		if (listOfTrustedListSources != null) {
			executeLOTLSourcesAnalysis(Arrays.asList(listOfTrustedListSources), dssFileLoader);

			// Check LOTLs consistency
			// Exception on duplicate TL URL

			// extract TLSources from cached LOTLs
		}

		// And then, execute all TLs (manual configs + TLs from LOTLs)
		executeTLSourcesAnalysis(currentTLSources, dssFileLoader);

		// alerts()

		// TLCerSource sync + cache sync if needed

		// cache cleaner (remove TO_BE_DELETED entries)
	}

	private void executeLOTLSourcesAnalysis(List<LOTLSource> lotlSources, DSSFileLoader dssFileLoader) {
		// get cache contents

		// no duplicate URL

		for (LOTLSource lotlSource : lotlSources) {
//			execute();
		}

		for (LOTLSource lotlSource : lotlSources) {
//			get();
		}

		// update caches

		// Analyse introduced changes for TLs + adapt cache for TLs (EXPIRED)
	}

	@SuppressWarnings("rawtypes")
	private void executeTLSourcesAnalysis(List<TLSource> tlSources, DSSFileLoader dssFileLoader) {
		LOG.info("Running TLAnalysis for {} TLSource(s)", tlSources.size());

		List<Future> futures = new ArrayList<Future>();
		for (TLSource tlSource : tlSources) {
			// Limited access to the caches
			final TLAnalysisCacheAccess cacheAccess = new TLAnalysisCacheAccess(tlSource.getCacheKey(), downloadCache, parsingCache, validationCache);
			futures.add(executorService.submit(new TLAnalysis(tlSource, cacheAccess, dssFileLoader)));
		}

		int nbDone = 0;
		for (Future future : futures) {
			try {
				if (future.get() == null) {
					nbDone++;
				}
			} catch (Exception e) {
				LOG.error("Unable to retrieve the thread result", e);
			}
		}

		LOG.info("TLAnalysis is DONE for {} TLSource(s) / {}", nbDone, tlSources.size());
	}

}
