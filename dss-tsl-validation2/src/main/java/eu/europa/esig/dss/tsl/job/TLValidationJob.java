package eu.europa.esig.dss.tsl.job;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.spi.client.http.DataLoader;
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

	public void setOnlineDataLoader(DataLoader onlineDataLoader) {
		this.onlineDataLoader = onlineDataLoader;
	}

	public void setTrustedListSources(TLSource... trustedListSources) {
		this.trustedListSources = trustedListSources;
	}

	public void setListOfTrustedListSources(LOTLSource... listOfTrustedListSources) {
		this.listOfTrustedListSources = listOfTrustedListSources;
	}

	public void setExecutorService(ExecutorService executorService) {
		if (this.executorService != null && !this.executorService.isShutdown()) {
			this.executorService.shutdownNow();
		}
		this.executorService = executorService;
	}

	public void init() {
//		refresh(cacheDataLoader);
	}

	public void refresh() {
		refresh(onlineDataLoader);
	}

	private void refresh(DataLoader dataLoader) {

		List<TLSource> currentTLSources = new ArrayList<TLSource>();
		if (trustedListSources != null) {
			currentTLSources = Arrays.asList(trustedListSources);
		}

		// Execute all LOTLs
		if (listOfTrustedListSources != null) {
			executeLOTLSourcesAnalysis(Arrays.asList(listOfTrustedListSources), dataLoader);

			// Check LOTLs consistency
			// Exception on duplicate TL URL

			// extract TLSources from cached LOTLs
		}

		// And then, execute all TLs (manual configs + TLs from LOTLs)
		executeTLSourcesAnalysis(currentTLSources, dataLoader);

		// alerts()

		// TLCerSource sync + cache sync if needed

		// cache cleaner (remove TO_BE_DELETED entries)
	}

	private void executeLOTLSourcesAnalysis(List<LOTLSource> lotlSources, DataLoader dataLoader) {
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
	private void executeTLSourcesAnalysis(List<TLSource> tlSources, DataLoader dataLoader) {

		List<Future> futures = new ArrayList<Future>();
		for (TLSource tlSource : tlSources) {
			// Limited access to the caches
			final TLAnalysisCacheAccess cacheAccess = new TLAnalysisCacheAccess(tlSource.getCacheKey(), downloadCache, parsingCache, validationCache);
			futures.add(executorService.submit(new TLAnalysis(tlSource, cacheAccess, dataLoader)));
		}

		for (Future future : futures) {
			try {
				future.get();
			} catch (Exception e) {
				LOG.error("Unable to retrieve the thread result", e);
			}
		}

	}

}
