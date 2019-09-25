package eu.europa.esig.dss.tsl.job;

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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.service.http.commons.DSSFileLoader;
import eu.europa.esig.dss.tsl.cache.CacheAccessByKey;
import eu.europa.esig.dss.tsl.cache.CacheAccessFactory;
import eu.europa.esig.dss.tsl.cache.CacheCleaner;
import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.ReadOnlyCacheAccess;
import eu.europa.esig.dss.tsl.parsing.AbstractParsingResult;
import eu.europa.esig.dss.tsl.runnable.LOTLAnalysis;
import eu.europa.esig.dss.tsl.runnable.LOTLWithPivotsAnalysis;
import eu.europa.esig.dss.tsl.runnable.TLAnalysis;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.tsl.summary.ValidationJobSummary;
import eu.europa.esig.dss.utils.Utils;

/**
 * The main class performing the TL/LOTL download / parsing / validation tasks
 *
 */
public class TLValidationJob {

	private static final Logger LOG = LoggerFactory.getLogger(TLValidationJob.class);

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
	 * Returns validation job summary for all processed LOTL / TLs
	 * @return {@link ValidationJobSummary}
	 */
	public ValidationJobSummary getSummary() {
		final List<TLSource> tlList = new ArrayList<TLSource>();
		if (Utils.isArrayNotEmpty(trustedListSources)) {
			tlList.addAll(Arrays.asList(trustedListSources));
		}
		final List<LOTLSource> lotlList = new ArrayList<LOTLSource>();
		if (Utils.isArrayNotEmpty(listOfTrustedListSources)) {
			lotlList.addAll(Arrays.asList(listOfTrustedListSources));
			tlList.addAll(extractTlSources(lotlList));
		}
		return new ValidationJobSummary(tlList, lotlList);
	}

	/**
	 * Used to execute the refresh in offline mode (no date from remote sources will be downloaded)
	 * By default used on initialization
	 */
	public void offlineRefresh() {
		Objects.requireNonNull(offlineLoader, "The offlineLoader must be defined!");
		refresh(offlineLoader);
	}

	/**
	 * Used to execute the refresh in online mode (all data will be updated from remote sources)
	 * Used as default database update.
	 */
	public void onlineRefresh() {
		Objects.requireNonNull(onlineLoader, "The onlineLoader must be defined!");
		refresh(onlineLoader);
	}

	private void refresh(DSSFileLoader dssFileLoader) {

		List<TLSource> currentTLSources = new ArrayList<TLSource>();
		if (trustedListSources != null) {
			currentTLSources = Arrays.asList(trustedListSources);
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

		// TLCerSource sync + cache sync if needed

		executeTLSourcesClean(currentTLSources, dssFileLoader);
	}

	private void executeLOTLSourcesAnalysis(List<LOTLSource> lotlSources, DSSFileLoader dssFileLoader) {
		checkNoDuplicateUrls(lotlSources);

		int nbLOTLSources = lotlSources.size();

		LOG.info("Running analysis for {} LOTLSource(s)", nbLOTLSources);

		Map<CacheKey, AbstractParsingResult> oldParsingValues = extractParsingCache(lotlSources);

		CountDownLatch latch = new CountDownLatch(nbLOTLSources);
		for (LOTLSource lotlSource : lotlSources) {
			final CacheAccessByKey cacheAccess = CacheAccessFactory.getCacheAccess(lotlSource.getCacheKey());
			if (lotlSource.isPivotSupport()) {
				executorService.submit(new LOTLWithPivotsAnalysis(lotlSource, cacheAccess, dssFileLoader, latch));
			} else {
				executorService.submit(new LOTLAnalysis(lotlSource, cacheAccess, dssFileLoader, latch));
			}
		}

		try {
			latch.await();
			LOG.info("Analysis is DONE for {} LOTLSource(s)", nbLOTLSources);
		} catch (InterruptedException e) {
			LOG.error("Interruption in the LOTLSource process", e);
		}

		Map<CacheKey, AbstractParsingResult> newParsingValues = extractParsingCache(lotlSources);

		// Analyze introduced changes for TLs + adapt cache for TLs (EXPIRED)
		LOTLChangeApplier lotlChangeApplier = new LOTLChangeApplier(oldParsingValues, newParsingValues);
		lotlChangeApplier.analyzeAndApply();
	}
	
	private List<TLSource> extractTlSources(List<LOTLSource> lotlList) {
		TLSourceBuilder tlSourceBuilder = new TLSourceBuilder(lotlList, extractParsingCache(lotlList));
		return tlSourceBuilder.build();
	}

	private Map<CacheKey, AbstractParsingResult> extractParsingCache(List<LOTLSource> lotlSources) {
		final ReadOnlyCacheAccess readOnlyCacheAccess = CacheAccessFactory.getReadOnlyCacheAccess();
		return lotlSources.stream().collect(Collectors.toMap(LOTLSource::getCacheKey, s -> readOnlyCacheAccess.getParsingResult(s.getCacheKey())));
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
			final CacheAccessByKey cacheAccess = CacheAccessFactory.getCacheAccess(tlSource.getCacheKey());
			executorService.submit(new TLAnalysis(tlSource, cacheAccess, dssFileLoader, latch));
		}

		try {
			latch.await();
			LOG.info("Analysis is DONE for {} TLSource(s)", nbTLSources);
		} catch (InterruptedException e) {
			LOG.error("Interruption in the TLAnalysis process", e);
		}
	}
	
	private void executeTLSourcesClean(List<TLSource> tlSources, DSSFileLoader dssFileLoader) {
		int nbTLSources = tlSources.size();
		LOG.info("Running CacheClean for {} TLSource(s)", nbTLSources);
		
		for (TLSource tlSource : tlSources) {
			final CacheAccessByKey cacheAccess = CacheAccessFactory.getCacheAccess(tlSource.getCacheKey());
			cacheCleaner.clean(cacheAccess);
		}
		
		LOG.info("CacheClean is DONE for {} TLSource(s)", nbTLSources);
	}

	/**
	 * Duplicate urls mean cache conflict.
	 * 
	 * @param sources
	 *                a list of TLSource
	 */
	private void checkNoDuplicateUrls(List<? extends TLSource> sources) {
		List<String> allUrls = sources.stream().map(s -> s.getUrl()).collect(Collectors.toList());
		Set<String> uniqueUrls = new HashSet<String>(allUrls);
		if (allUrls.size() > uniqueUrls.size()) {
			throw new DSSException(String.format("Duplicate urls found : %s", allUrls));
		}
	}

}
