package eu.europa.esig.dss.tsl.job;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
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
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.DSSFileLoader;
import eu.europa.esig.dss.tsl.cache.CacheAccessByKey;
import eu.europa.esig.dss.tsl.cache.CacheCleaner;
import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.DownloadCache;
import eu.europa.esig.dss.tsl.cache.ParsingCache;
import eu.europa.esig.dss.tsl.cache.ValidationCache;
import eu.europa.esig.dss.tsl.cache.state.CachedEntry;
import eu.europa.esig.dss.tsl.dto.OtherTSLPointerDTO;
import eu.europa.esig.dss.tsl.parsing.AbstractParsingResult;
import eu.europa.esig.dss.tsl.parsing.LOTLParsingResult;
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
		if (listOfTrustedListSources != null) {
			executeLOTLSourcesAnalysis(Arrays.asList(listOfTrustedListSources), dssFileLoader);

			// Check LOTLs consistency

			// extract TLSources from cached LOTLs
		}

		// And then, execute all TLs (manual configs + TLs from LOTLs)
		executeTLSourcesAnalysis(currentTLSources, dssFileLoader);

		// alerts()

		// TLCerSource sync + cache sync if needed

		executeTLSourcesClean(currentTLSources, dssFileLoader);
	}

	private void executeLOTLSourcesAnalysis(List<LOTLSource> lotlSources, DSSFileLoader dssFileLoader) {
		checkNoDuplicateUrls(lotlSources);

		Map<CacheKey, CachedEntry<AbstractParsingResult>> oldParsingValues = extractParsingCache(lotlSources);

		for (LOTLSource lotlSource : lotlSources) {
//			execute();
		}

		for (LOTLSource lotlSource : lotlSources) {
//			get();
		}

		Map<CacheKey, CachedEntry<AbstractParsingResult>> newParsingValues = extractParsingCache(lotlSources);

		// Analyse introduced changes for TLs + adapt cache for TLs (EXPIRED)
		analyzeTLChanges(oldParsingValues, newParsingValues);
	}

	private Map<CacheKey, CachedEntry<AbstractParsingResult>> extractParsingCache(List<LOTLSource> lotlSources) {
		return lotlSources.stream().collect(Collectors.toMap(LOTLSource::getCacheKey, s -> parsingCache.get(s.getCacheKey())));
	}

	private void analyzeTLChanges(Map<CacheKey, CachedEntry<AbstractParsingResult>> oldParsingValues,
			Map<CacheKey, CachedEntry<AbstractParsingResult>> newParsingValues) {

		for (CacheKey lotlCacheKey : oldParsingValues.keySet()) {
			Map<String, List<CertificateToken>> oldUrlCerts = getTLPointers(oldParsingValues.get(lotlCacheKey));
			Map<String, List<CertificateToken>> newUrlCerts = getTLPointers(newParsingValues.get(lotlCacheKey));

			detectUrlChanges(oldUrlCerts, newUrlCerts);
			detectSigCertsChanges(oldUrlCerts, newUrlCerts);
		}

	}

	private void detectUrlChanges(Map<String, List<CertificateToken>> oldUrlCerts, Map<String, List<CertificateToken>> newUrlCerts) {
		for (String oldUrl : oldUrlCerts.keySet()) {
			if (!newUrlCerts.containsKey(oldUrl)) {
				LOG.info("Expired TL URL : {}", oldUrl);
				CacheKey oldKey = new CacheKey(oldUrl);
				downloadCache.toBeDeleted(oldKey);
				parsingCache.toBeDeleted(oldKey);
				validationCache.toBeDeleted(oldKey);
			}
		}
	}

	private void detectSigCertsChanges(Map<String, List<CertificateToken>> oldUrlCerts, Map<String, List<CertificateToken>> newUrlCerts) {
		for (String newUrl : newUrlCerts.keySet()) {
			List<CertificateToken> oldCerts = oldUrlCerts.get(newUrl);
			List<CertificateToken> newCerts = newUrlCerts.get(newUrl);
			if (oldCerts == null || !oldCerts.equals(newCerts)) {
				LOG.info("Signing certificates change detected for TL URL : {}", newUrl);
				CacheKey cacheKey = new CacheKey(newUrl);
				validationCache.expire(cacheKey);
			}
		}
	}

	private Map<String, List<CertificateToken>> getTLPointers(CachedEntry<AbstractParsingResult> cachedEntry) {
		if (cachedEntry != null && !cachedEntry.isEmpty()) {
			LOTLParsingResult parsingResult = (LOTLParsingResult) cachedEntry.getCachedResult();
			List<OtherTSLPointerDTO> tlPointers = parsingResult.getTlPointers();
			return tlPointers.stream().collect(Collectors.toMap(OtherTSLPointerDTO::getLocation, s -> s.getCertificates()));
		}
		return Collections.emptyMap();
	}

	private void executeTLSourcesAnalysis(List<TLSource> tlSources, DSSFileLoader dssFileLoader) {
		int nbTLSources = tlSources.size();
		if (nbTLSources == 0) {
			LOG.info("No TL to be analyzed");
			return;
		}

		checkNoDuplicateUrls(tlSources);

		LOG.info("Running TLAnalysis for {} TLSource(s)", nbTLSources);

		CountDownLatch latch = new CountDownLatch(nbTLSources);
		for (TLSource tlSource : tlSources) {
			final CacheAccessByKey cacheAccess = new CacheAccessByKey(tlSource.getCacheKey(), downloadCache, parsingCache, validationCache);
			executorService.submit(new TLAnalysis(tlSource, cacheAccess, dssFileLoader, latch));
		}

		try {
			latch.await();
			LOG.info("TLAnalysis is DONE for {} TLSource(s)", nbTLSources);
		} catch (InterruptedException e) {
			LOG.error("Interruption in the TLAnalysis process", e);
		}
	}
	
	private void executeTLSourcesClean(List<TLSource> tlSources, DSSFileLoader dssFileLoader) {
		int nbTLSources = tlSources.size();
		LOG.info("Running CacheClean for {} TLSource(s)", nbTLSources);
		
		for (TLSource tlSource : tlSources) {
			final CacheAccessByKey cacheAccess = new CacheAccessByKey(tlSource.getCacheKey(), downloadCache, parsingCache, validationCache);
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
