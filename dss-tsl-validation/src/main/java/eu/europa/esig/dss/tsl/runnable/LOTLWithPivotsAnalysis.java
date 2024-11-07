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
package eu.europa.esig.dss.tsl.runnable;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.access.CacheAccessByKey;
import eu.europa.esig.dss.tsl.cache.access.CacheAccessFactory;
import eu.europa.esig.dss.tsl.cache.access.ReadOnlyCacheAccess;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.dto.ValidationCacheDTO;
import eu.europa.esig.dss.tsl.sha2.Sha2FileCacheDataLoader;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.validation.TLValidatorTask;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Runs the job for a LOTL with pivots analysis
 *
 */
public class LOTLWithPivotsAnalysis extends LOTLAnalysis {

	private static final Logger LOG = LoggerFactory.getLogger(LOTLWithPivotsAnalysis.class);

	/** Loads a relevant cache access object */
	private final CacheAccessFactory cacheAccessFactory;

	/** The file loader */
	private final DSSFileLoader dssFileLoader;

	/**
	 * Default constructor
	 *
	 * @param source             {@link LOTLSource}
	 * @param cacheAccess        {@link CacheAccessByKey}
	 * @param cacheAccessFactory {@link CacheAccessFactory}
	 * @param dssFileLoader      {@link DSSFileLoader}
	 * @param latch              {@link CountDownLatch}
	 */
	public LOTLWithPivotsAnalysis(final LOTLSource source, final CacheAccessByKey cacheAccess,
								  final DSSFileLoader dssFileLoader, final CacheAccessFactory cacheAccessFactory, final CountDownLatch latch) {
		super(source, cacheAccess, dssFileLoader, latch);
		this.cacheAccessFactory = cacheAccessFactory;
		this.dssFileLoader = dssFileLoader;
	}

	@Override
	protected CertificateSource getCurrentCertificateSource() {
		final CertificateSource initialCertificateSource = super.getCurrentCertificateSource();

		CertificateSource currentCertificateSource;

		ParsingCacheDTO currentLOTLParsing = getCacheAccessByKey().getParsingReadOnlyResult();
		if (currentLOTLParsing != null) {
			List<String> pivotURLs = currentLOTLParsing.getPivotUrls();
			if (Utils.isCollectionEmpty(pivotURLs)) {
				LOG.trace("No pivot LOTL found");
				currentCertificateSource = initialCertificateSource;
			} else {
				currentCertificateSource = getCurrentCertificateSourceFromPivots(initialCertificateSource, pivotURLs);
			}
		} else {
			LOG.warn("Unable to retrieve the parsing result for the current LOTL (allowed signing certificates set from the configuration)");
			currentCertificateSource = initialCertificateSource;
		}

		return currentCertificateSource;
	}

	private CertificateSource getCurrentCertificateSourceFromPivots(CertificateSource initialCertificateSource, List<String> pivotURLs) {

		/*-
		* current 																						-> Signed with pivot 226 certificates
		* https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-226-mp.xml	-> Signed with pivot 191 certificates
		* https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-191-mp.xml	-> Signed with pivot 172 certificates
		* https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-172-mp.xml 	-> Signed with OJ Certs
		* http://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2016.233.01.0001.01.ENG		-> OJ
		*/

		Map<String, PivotProcessingResult> processingResults = downloadAndParseAllPivots(pivotURLs);

		ReadOnlyCacheAccess readOnlyCacheAccess = cacheAccessFactory.getReadOnlyCacheAccess();

		List<String> pivotUrlsReversed = Utils.reverseList(pivotURLs); // -> 172, 191,..

		CertificateSource currentCertificateSource = initialCertificateSource;
		for (String pivotUrl : pivotUrlsReversed) {
			CacheKey cacheKey = new CacheKey(pivotUrl);

			PivotProcessingResult pivotProcessingResult = processingResults.get(pivotUrl);
			if (pivotProcessingResult != null) {
				CacheAccessByKey pivotCacheAccess = cacheAccessFactory.getCacheAccess(cacheKey);
				validationPivot(pivotCacheAccess, pivotProcessingResult.getPivot(), currentCertificateSource);

				ValidationCacheDTO validationResult = readOnlyCacheAccess.getValidationCacheDTO(cacheKey);
				if (validationResult != null) {
					if (validationResult.isValid()) {
						currentCertificateSource = pivotProcessingResult.getCertificateSource();
					} else {
						LOG.warn("Pivot LOTL '{}' is not valid ({}/{})", pivotUrl, validationResult.getIndication(), validationResult.getSubIndication());
					}
				} else {
					LOG.warn("No validation result found for Pivot LOTL '{}'", pivotUrl);
				}
			} else {
				LOG.warn("No processing result for Pivot LOTL '{}'", pivotUrl);
			}
		}

		return currentCertificateSource;
	}

	private void validationPivot(CacheAccessByKey pivotCacheAccess, DSSDocument document, CertificateSource certificateSource) {
		// True if EMPTY / EXPIRED by TL/LOTL
		if (pivotCacheAccess.isValidationRefreshNeeded()) {
			try {
				LOG.debug("Validating the Pivot LOTL with cache key '{}'...", pivotCacheAccess.getCacheKey().getKey());
				TLValidatorTask validationTask = new TLValidatorTask(document, certificateSource);
				pivotCacheAccess.update(validationTask.get());
			} catch (Exception e) {
				LOG.warn("Cannot validate the Pivot LOTL with the cache key '{}' : {}", pivotCacheAccess.getCacheKey().getKey(), e.getMessage());
				assertOriginalDocumentIsAccessible(pivotCacheAccess);
				pivotCacheAccess.validationError(e);
			}
		}
	}

	private void assertOriginalDocumentIsAccessible(CacheAccessByKey pivotCacheAccess) {
		// set the exception in order to avoid potential deadlock (file does not exist, but download result is present)
		try {
			if (pivotCacheAccess.getDownloadReadOnlyResult() != null
					&& DSSUtils.isEmpty(pivotCacheAccess.getDownloadReadOnlyResult().getDocument())) {
				LOG.warn("The Pivot LOTL with the cache key '{}' contains empty content", pivotCacheAccess.getCacheKey().getKey());
				throw new DSSException("Empty content file is obtained!");
			}
		} catch (Exception e) {
			LOG.warn("The Pivot LOTL with the cache key '{}' contains empty content : {}", pivotCacheAccess.getCacheKey().getKey(), e.getMessage());
			pivotCacheAccess.downloadError(e);
			pivotCacheAccess.parsingError(e);
		}
	}

	private Map<String, PivotProcessingResult> downloadAndParseAllPivots(List<String> pivotURLs) {
		final Map<String, PivotProcessingResult> processingResults = new HashMap<>();

		LOTLSource lotlSource = (LOTLSource) getSource();
		CacheAccessByKey lotlCacheAccessByKey = getCacheAccessByKey();
		Map<String, PivotProcessing> pivotProcessingMap = new HashMap<>();
		List<CacheAccessByKey> pivotCacheAccessByKeyList = new ArrayList<>();
		for (String pivotUrl : pivotURLs) {
			CacheAccessByKey pivotCacheAccess = cacheAccessFactory.getCacheAccess(new CacheKey(pivotUrl));

			if (lotlCacheAccessByKey.isValidationRefreshNeeded() || pivotCacheAccess.isValidationRefreshNeeded()
					|| !pivotCacheAccess.getDownloadReadOnlyResult().isResultExist()) {
				LOTLSource pivotSource = new LOTLSource();
				pivotSource.setUrl(pivotUrl);
				pivotSource.setLotlPredicate(lotlSource.getLotlPredicate());
				pivotSource.setTlPredicate(lotlSource.getTlPredicate());
				pivotSource.setPivotSupport(lotlSource.isPivotSupport());

				// .sha2 is not supported by pivot
				DSSFileLoader dataLoader = dssFileLoader instanceof Sha2FileCacheDataLoader ?
						((Sha2FileCacheDataLoader) dssFileLoader).getDataLoader() : dssFileLoader;
				pivotProcessingMap.put(pivotUrl, new PivotProcessing(pivotSource, pivotCacheAccess, getCacheAccessByKey(),
						new ArrayList<>(pivotCacheAccessByKeyList), dataLoader));

			} else {
				// if exists and no update is required
				processingResults.put(pivotUrl, new PivotProcessingResultFromCacheAccessBuilder(pivotCacheAccess).build());
			}

			pivotCacheAccessByKeyList.add(pivotCacheAccess);
		}

		if (Utils.isMapNotEmpty(pivotProcessingMap)) {
			ExecutorService executorService = Executors.newFixedThreadPool(pivotProcessingMap.size());
			Map<String, Future<PivotProcessingResult>> futures = new HashMap<>();
			for (Map.Entry<String, PivotProcessing> processing : pivotProcessingMap.entrySet()) {
				futures.put(processing.getKey(), executorService.submit(processing.getValue()));
			}

			for (Entry<String, Future<PivotProcessingResult>> entry : futures.entrySet()) {
				try {
					processingResults.put(entry.getKey(), entry.getValue().get());
				} catch (InterruptedException e) {
					LOG.error(String.format("Unable to retrieve the PivotProcessingResult for url '%s'", entry.getKey()), e);
					Thread.currentThread().interrupt();
				} catch (ExecutionException e) {
					LOG.error(String.format("Unable to retrieve the PivotProcessingResult for url '%s'", entry.getKey()), e);
				}
			}
			shutdownAndAwaitTermination(executorService);
		}

		return processingResults;
	}

	private void shutdownAndAwaitTermination(ExecutorService executorService) {
		executorService.shutdown();
		try {
			if (!executorService.awaitTermination(10, TimeUnit.SECONDS)) {
				shutdownNowAndAwaitTermination(executorService);
			}
		} catch (InterruptedException e) {
			shutdownNowAndAwaitTermination(executorService);
			Thread.currentThread().interrupt();
		}
	}

	private void shutdownNowAndAwaitTermination(ExecutorService executorService) {
		executorService.shutdownNow();
		try {
			if (!executorService.awaitTermination(10, TimeUnit.SECONDS)) {
				LOG.warn("More than 10s to terminate the service executor");
			}
		} catch (InterruptedException e) {
			LOG.warn("Unable to interrupt the service executor", e);
			Thread.currentThread().interrupt();
		}
	}

}
