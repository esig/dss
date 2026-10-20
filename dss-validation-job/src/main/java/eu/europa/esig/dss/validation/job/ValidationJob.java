/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.job;

import eu.europa.esig.dss.alert.Alert;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.job.DocumentInfo;
import eu.europa.esig.dss.model.job.DocumentListInfo;
import eu.europa.esig.dss.model.job.ParsingInfoRecord;
import eu.europa.esig.dss.model.job.ValidationJobSummary;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.job.alerts.ValidationJobAlerter;
import eu.europa.esig.dss.validation.job.cache.CacheCleaner;
import eu.europa.esig.dss.validation.job.cache.CacheKey;
import eu.europa.esig.dss.validation.job.cache.access.CacheAccessByKey;
import eu.europa.esig.dss.validation.job.cache.access.CacheAccessFactory;
import eu.europa.esig.dss.validation.job.cache.access.ReadOnlyCacheAccess;
import eu.europa.esig.dss.validation.job.source.DocumentSource;
import eu.europa.esig.dss.validation.job.summary.ValidationJobSummaryBuilder;
import eu.europa.esig.dss.validation.job.sync.AcceptAllStrategy;
import eu.europa.esig.dss.validation.job.sync.SynchronizationStrategy;
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
 * The main class performing the document download / parsing / validation tasks
 *
 * @param <D> current {@link DocumentInfo}
 * @param <L> parent {@link DocumentListInfo}
 * @param <C> {@link CacheAccessFactory}
 */
public abstract class ValidationJob<D extends DocumentInfo, L extends DocumentListInfo<D>, C extends CacheAccessFactory> {

	private static final Logger LOG = LoggerFactory.getLogger(ValidationJob.class);

	/**
	 * Contains all caches for the current validation job
	 */
	private final C cacheAccessFactory;

	/**
	 * Provides methods to manage the asynchronous behaviour
	 */
	private ExecutorService executorService = Executors.newCachedThreadPool();

	/**
	 * Array of zero, one or more document sources.
	 * <p>
	 * These trusted lists are not referenced in a document list(s).
	 */
	private DocumentSource[] documentSources;

	/**
	 * Array of zero, one or more document list sources.
	 */
	private DocumentSource[] documentListSources;
	
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
	 * The strategy to follow to synchronize the certificates.
	 * <p>
	 * Default : all documents and document lists are synchronized
	 */
	private SynchronizationStrategy<D, L> synchronizationStrategy = new AcceptAllStrategy<D, L>();

	/**
	 * This property allows printing the cache content before and after the
	 * synchronization (default : false)
	 */
	private boolean debug = false;
	
	/**
     * List of document list info alerts
     */
    private List<Alert<L>> documentListAlerts;
	
	/**
     * List of document info alerts
     */
    private List<Alert<D>> documentAlerts;

	/**
	 * Validation policy containing constraints for downloaded documents validation
	 */
	private ValidationPolicy validationPolicy;

	/**
	 * Default constructor instantiating object with null configuration
	 *
	 * @param cacheAccessFactory {@link CacheAccessFactory}
	 */
	protected ValidationJob(final C cacheAccessFactory) {
		this.cacheAccessFactory = cacheAccessFactory;
	}

	/**
	 * Gets the cache access factory
	 *
	 * @return {@link CacheAccessFactory}
	 */
	protected C getCacheAccessFactory() {
		return cacheAccessFactory;
	}

	/**
	 * Gets independent document sources
	 *
	 * @return {@link  DocumentSource}s
	 */
	protected DocumentSource[] getDocumentSources() {
		return documentSources;
	}

	/**
	 * Sets the additional document sources
	 *
	 * @param documentSources {@link DocumentSource}s
	 */
	protected void setDocumentSources(DocumentSource... documentSources) {
		this.documentSources = documentSources;
	}

	/**
	 * Gets document list sources
	 *
	 * @return {@link  DocumentSource}s
	 */
	protected DocumentSource[] getDocumentListSources() {
		return documentListSources;
	}

	/**
	 * Sets the document lists sources
	 *
	 * @param documentListSources {@link DocumentSource}s
	 */
	protected void setDocumentListSources(DocumentSource... documentListSources) {
		this.documentListSources = documentListSources;
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
	 * Gets the synchronization strategy
	 *
	 * @return {@link SynchronizationStrategy}
	 */
	protected SynchronizationStrategy<D, L> getSynchronizationStrategy() {
		return synchronizationStrategy;
	}

	/**
	 * Sets the strategy to follow for the certificate synchronization
	 * 
	 * @param synchronizationStrategy
	 *                                the different options for the certificate
	 *                                synchronization
	 */
	public void setSynchronizationStrategy(SynchronizationStrategy<D, L> synchronizationStrategy) {
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
	 * Sets the document list alerts to be processed
	 * 
	 * @param documentListAlerts a list of {@link Alert}s
	 */
	public void setDocumentListAlerts(List<Alert<L>> documentListAlerts) {
	    this.documentListAlerts = documentListAlerts;
	}
	
	/**
	 * Sets the document alerts to be processed
	 * 
	 * @param documentAlerts a list of {@link Alert}s
	 */
	public void setDocumentAlerts(List<Alert<D>> documentAlerts) {
	    this.documentAlerts = documentAlerts;
	}

	/**
	 * Gets the validation policy to perform the document validation task.
	 * If not provided, loads the default policy.
	 *
	 * @return {@link ValidationPolicy}
	 */
	public ValidationPolicy getValidationPolicy() {
		if (validationPolicy == null) {
			validationPolicy = loadDefaultValidationPolicy();
		}
		return validationPolicy;
	}

	/**
	 * Loads the default validation policy for the given document type
	 *
	 * @return {@link ValidationPolicy}
	 */
	protected abstract ValidationPolicy loadDefaultValidationPolicy();

	/**
	 * Sets a validation policy to be used on document validation
	 *
	 * @param validationPolicy {@link ValidationPolicy}
	 */
	public void setValidationPolicy(ValidationPolicy validationPolicy) {
		this.validationPolicy = validationPolicy;
	}

	/**
	 * Returns validation job summary for all processed documents / document lists
	 * @return {@link ValidationJobSummary}
	 */
	public synchronized ValidationJobSummary<D, L> getSummary() {
		return getValidationJobSummaryBuilder().build();
	}

	/**
	 * Instantiates a builder to create a {@code ValidationJobSummary}
	 *
	 * @return {@link ValidationJobSummaryBuilder}
	 */
	protected abstract ValidationJobSummaryBuilder<D, L> getValidationJobSummaryBuilder();

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
		List<DocumentSource> currentDocSources = new ArrayList<>();
		if (documentSources != null) {
			currentDocSources.addAll(Arrays.asList(documentSources));
		}

		// Execute all document lists
		if (Utils.isArrayNotEmpty(documentListSources)) {
			final List<DocumentSource> docLists = Arrays.asList(documentListSources);

			executeDocumentListSourcesAnalysis(docLists, dssFileLoader);

			// Check document lists consistency

			// extract document sources from cached document lists
			currentDocSources.addAll(extractOtherDocumentSources());
		}

		// And then, execute all TLs (manual configs + documents from document lists)
		executeDocumentSourcesAnalysis(currentDocSources, dssFileLoader);

		// alerts()
		if (Utils.isCollectionNotEmpty(documentListAlerts) || Utils.isCollectionNotEmpty(documentAlerts)) {
			ValidationJobSummary<D, L> jobSummary = getSummary();
			ValidationJobAlerter<D, L> alerter = new ValidationJobAlerter<>(documentListAlerts, documentAlerts);
			alerter.detectChanges(jobSummary);
		}

		if (debug) {
			LOG.info("Dump before synchronization");
			getCacheAccessFactory().getDebugCacheAccess().dump();
		}

		// certificate source sync + cache sync if needed
		synchronizeCertificateSources();

		executeCacheCleaner();

		if (debug) {
			LOG.info("Dump after synchronization");
			getCacheAccessFactory().getDebugCacheAccess().dump();
		}
	}

	private void executeDocumentListSourcesAnalysis(List<DocumentSource> docListSources, DSSFileLoader dssFileLoader) {
		int nbDocListSources = docListSources.size();
		if (nbDocListSources == 0) {
			LOG.debug("No document list sources are to be analyzed");
			return;
		}

		checkNoDuplicateUrls(docListSources);

		LOG.info("Running analysis for {} {}(s)", nbDocListSources, docListSources.get(0).getClass().getSimpleName());

		Map<CacheKey, ParsingInfoRecord> oldParsingValues = extractParsingCache(docListSources);

		CountDownLatch latch = new CountDownLatch(nbDocListSources);
		for (DocumentSource docListSource : docListSources) {
			executorService.submit(getDocumentListAnalysis(docListSource, dssFileLoader, latch));
		}

		try {
			latch.await();
			LOG.info("Analysis is DONE for {} {}(s)", nbDocListSources, docListSources.get(0).getClass().getSimpleName());
		} catch (InterruptedException e) {
			LOG.error("Interruption in the document list analysis process", e);
			Thread.currentThread().interrupt();
		}

		Map<CacheKey, ParsingInfoRecord> newParsingValues = extractParsingCache(docListSources);

		handleDocumentChanges(oldParsingValues, newParsingValues);
	}

	/**
	 * Gets a Runnable object to perform an analysis of a document
	 *
	 * @param documentSource {@link DocumentSource}
	 * @param dssFileLoader {@link DSSFileLoader}
	 * @param latch {@link CountDownLatch}
	 * @return {@link Runnable}
	 */
	protected abstract Runnable getDocumentAnalysis(DocumentSource documentSource, DSSFileLoader dssFileLoader, CountDownLatch latch);

	/**
	 * Gets a Runnable object to perform an analysis of a document list
	 *
	 * @param documentSource {@link DocumentSource}
	 * @param dssFileLoader {@link DSSFileLoader}
	 * @param latch {@link CountDownLatch}
	 * @return {@link Runnable}
	 */
	protected abstract Runnable getDocumentListAnalysis(DocumentSource documentSource, DSSFileLoader dssFileLoader, CountDownLatch latch);

	/**
	 * Extracts other document sources from a collection of document lists
	 *
	 * @return a list of {@link DocumentSource}s
	 */
	protected abstract List<? extends DocumentSource> extractOtherDocumentSources();

	/**
	 * Executes logic on occurred document changes
	 *
	 * @param oldParsingValues old map between document cache keys and parsing results
	 * @param newParsingValues new map between document cache keys and parsing results
	 */
	protected abstract void handleDocumentChanges(Map<CacheKey, ParsingInfoRecord> oldParsingValues, Map<CacheKey, ParsingInfoRecord> newParsingValues);
	
    private Map<CacheKey, ParsingInfoRecord> extractParsingCache(List<DocumentSource> docListSources) {
        final ReadOnlyCacheAccess readOnlyCacheAccess = getCacheAccessFactory().getReadOnlyCacheAccess();
        return docListSources.stream().collect(Collectors.toMap(DocumentSource::getCacheKey,
				s -> readOnlyCacheAccess.getParsingInfoRecord(s.getCacheKey())));
    }

	private void executeDocumentSourcesAnalysis(List<DocumentSource> docSources, DSSFileLoader dssFileLoader) {
		int nbDocSources = docSources.size();
		if (nbDocSources == 0) {
			LOG.info("No document sources are to be analyzed");
			return;
		}

		checkNoDuplicateUrls(docSources);

		LOG.info("Running analysis for {} {}(s)", nbDocSources, docSources.get(0).getClass().getSimpleName());

		CountDownLatch latch = new CountDownLatch(nbDocSources);
		for (DocumentSource docSource : docSources) {
			executorService.submit(getDocumentAnalysis(docSource, dssFileLoader, latch));
		}

		try {
			latch.await();
			LOG.info("Analysis is DONE for {} {}(s)", nbDocSources, docSources.get(0).getClass().getSimpleName());
		} catch (InterruptedException e) {
			LOG.error("Interruption in the document analysis process", e);
			Thread.currentThread().interrupt();
		}
	}

	/**
	 * Synchronizes the certificate source, if applicable
	 */
	protected abstract void synchronizeCertificateSources();

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
	 *                a list of document sources
	 */
	private void checkNoDuplicateUrls(List<DocumentSource> sources) {
		List<String> allUrls = sources.stream().map(DocumentSource::getUrl).collect(Collectors.toList());
		Set<String> uniqueUrls = new HashSet<>(allUrls);
		if (allUrls.size() > uniqueUrls.size()) {
			throw new DSSException(String.format("Duplicate urls found : %s", allUrls));
		}
	}

}
