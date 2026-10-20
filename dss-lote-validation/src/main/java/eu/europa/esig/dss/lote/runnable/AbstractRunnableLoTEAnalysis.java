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
package eu.europa.esig.dss.lote.runnable;

import eu.europa.esig.dss.lote.source.LoTESource;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.validation.job.cache.access.CacheAccessByKey;
import eu.europa.esig.dss.validation.job.download.DownloadResult;
import eu.europa.esig.dss.validation.job.download.DownloadTask;
import eu.europa.esig.dss.validation.job.parsing.ParsingTask;
import eu.europa.esig.dss.validation.job.validation.ValidationTask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.concurrent.CountDownLatch;

/**
 * Abstract class to perform an analysis of a TS 119 602 List of Trusted Entities
 *
 * @param <S> {@link LoTESource}
 */
public abstract class AbstractRunnableLoTEAnalysis<S extends LoTESource> implements Runnable {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractRunnableLoTEAnalysis.class);

    private static final String LOG_ERROR_PERFORM_ANALYSIS = "Error performing analysis.";

    /** The List source */
    private final S source;

    /** The cache access of the record */
    private final CacheAccessByKey cacheAccess;

    /** The file loader */
    private final DSSFileLoader dssFileLoader;

    /** The tasks counter */
    private final CountDownLatch latch;

    /** Validation policy constraints */
    private final ValidationPolicy validationPolicy;

    /**
     * Default constructor
     *
     * @param source {@link LoTESource} representing a List to be processed
     * @param cacheAccess {@link CacheAccessByKey}
     * @param dssFileLoader {@link DSSFileLoader}
     * @param latch {@link CountDownLatch}
     * @deprecated since DSS 6.6. Please use
     *             {@link AbstractRunnableLoTEAnalysis(S, CacheAccessByKey, DSSFileLoader, CountDownLatch, ValidationPolicy)} instead
     */
    @Deprecated
    protected AbstractRunnableLoTEAnalysis(final S source, final CacheAccessByKey cacheAccess,
                                           final DSSFileLoader dssFileLoader, final CountDownLatch latch) {
        this(source, cacheAccess, dssFileLoader, latch, null);
    }

    /**
     * Default constructor
     *
     * @param source {@link LoTESource} representing a List to be processed
     * @param cacheAccess {@link CacheAccessByKey}
     * @param dssFileLoader {@link DSSFileLoader}
     * @param latch {@link CountDownLatch}
     */
    protected AbstractRunnableLoTEAnalysis(final S source, final CacheAccessByKey cacheAccess,
                                           final DSSFileLoader dssFileLoader, final CountDownLatch latch,
                                           ValidationPolicy validationPolicy) {
        Objects.requireNonNull(source, "Source cannot be null");
        Objects.requireNonNull(cacheAccess, "CacheAccessByKey cannot be null");
        Objects.requireNonNull(dssFileLoader, "DSSFileLoader cannot be null");
        Objects.requireNonNull(latch, "CountDownLatch cannot be null");

        this.source = source;
        this.cacheAccess = cacheAccess;
        this.dssFileLoader = dssFileLoader;
        this.latch = latch;
        this.validationPolicy = validationPolicy;
    }

    /**
     * Returns the current {@code LoTESource}
     *
     * @return {@link LoTESource}
     */
    protected final S getSource() {
        return source;
    }

    /**
     * Performs analysis
     */
    protected void doAnalyze() {
        String url = getSource().getUrl();

        DSSDocument document = null;
        ILoTEAnalysisExecutor<S> analysisExecutor = null;
        try {
            LOG.debug("Downloading url '{}'...", url);
            document = dssFileLoader.getDocument(url);
            analysisExecutor = getAnalysisExecutor(document);

        } catch (Exception e) {
            // wrapped exception
            LOG.warn(e.getMessage());
            cacheAccess.downloadError(e);
            return;
        }

        document = download(analysisExecutor, document, url);
        if (document != null) {
            parsing(analysisExecutor, document);
            validation(analysisExecutor, document);
        }
    }

    /**
     * Gets executor to perform LoTE analysis
     *
     * @param document {@link DSSDocument}
     * @return {@link ILoTEAnalysisExecutor}
     */
    protected abstract ILoTEAnalysisExecutor<S> getAnalysisExecutor(DSSDocument document);

    /**
     * Downloads the document by url
     *
     * @param analysisExecutor {@link ILoTEAnalysisExecutor}
     * @param document {@link DSSDocument}
     * @param url {@link String}
     * @return {@link DSSDocument}
     */
    protected DSSDocument download(final ILoTEAnalysisExecutor<S> analysisExecutor, final DSSDocument document, final String url) {
        try {
            DownloadTask downloadTask = analysisExecutor.getDownloadTask(document, url);
            DownloadResult downloadResult = downloadTask.get();
            if (!cacheAccess.isUpToDate(downloadResult)) {
                cacheAccess.update(downloadResult);
                expireCache();
            }
            return downloadResult.getDSSDocument();

        } catch (Exception e) {
            // wrapped exception
            LOG.warn(e.getMessage());
            cacheAccess.downloadError(e);
        }
        return null;
    }

    /**
     * This method expires the cache in order to trigger the corresponding tasks on refresh
     */
    protected void expireCache() {
        cacheAccess.expireParsing();
        cacheAccess.expireValidation();
    }

    /**
     * Parses the document
     *
     * @param analysisExecutor {@link ILoTEAnalysisExecutor}
     * @param document {@link DSSDocument} to parse
     */
    protected void parsing(final ILoTEAnalysisExecutor<S> analysisExecutor, DSSDocument document) {
        // True if EMPTY / REFRESH_REQUIRED
        if (cacheAccess.isParsingRefreshNeeded()) {
            try {
                LOG.debug("Parsing the LoTE/LoLoTE with cache key '{}'...", cacheAccess.getCacheKey().getKey());
                ParsingTask parsingTask = analysisExecutor.getParsingTask(document, getSource());
                cacheAccess.update(parsingTask.get());
            } catch (Exception e) {
                LOG.warn("Cannot parse the LoTE/LoLoTE with the cache key '{}' : {}", cacheAccess.getCacheKey().getKey(), e.getMessage(), e);
                cacheAccess.parsingError(e);
            }
        }
    }

    /**
     * Validates the document
     *
     * @param analysisExecutor {@link ILoTEAnalysisExecutor}
     * @param document {@link DSSDocument} to validate
     */
    protected void validation(final ILoTEAnalysisExecutor<S> analysisExecutor, DSSDocument document) {
        // True if EMPTY / REFRESH_REQUIRED
        if (cacheAccess.isValidationRefreshNeeded()) {
            try {
                LOG.debug("Validating the LoTE/LoLoTE with cache key '{}'...", cacheAccess.getCacheKey().getKey());
                ValidationTask validationTask = analysisExecutor.getValidationTask(document, getCurrentCertificateSource(), validationPolicy);
                cacheAccess.update(validationTask.get());
            } catch (Exception e) {
                LOG.warn("Cannot validate the LoTE/LoLoTE with the cache key '{}' : {}", cacheAccess.getCacheKey().getKey(), e.getMessage());
                cacheAccess.validationError(e);
            }
        }
    }

    /**
     * Returns the certificate source to be used to validate LoTE/LoLoTE
     *
     * @return {@link CertificateSource}
     */
    protected CertificateSource getCurrentCertificateSource() {
        return getSource().getCertificateSource();
    }

    @Override
    public void run() {
        try {
            this.doAnalyze();
        } catch (final Throwable exception) {
            // NOTE: Throwable shall be caught
            LOG.warn(LOG_ERROR_PERFORM_ANALYSIS, exception);
        } finally {
            latch.countDown();
        }
    }

}
