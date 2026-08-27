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
package eu.europa.esig.dss.lote.job;

import eu.europa.esig.dss.lote.cache.access.LoTECacheAccessByKey;
import eu.europa.esig.dss.lote.cache.access.LoTECacheAccessFactory;
import eu.europa.esig.dss.lote.dto.LoTEParsingCacheDTO;
import eu.europa.esig.dss.lote.runnable.LoLoTEAnalysis;
import eu.europa.esig.dss.lote.runnable.LoTEAnalysis;
import eu.europa.esig.dss.lote.source.LoLoTESource;
import eu.europa.esig.dss.lote.source.LoTESource;
import eu.europa.esig.dss.lote.summary.LoTEValidationJobSummaryBuilder;
import eu.europa.esig.dss.lote.sync.LoTECertificateSourceSynchronizer;
import eu.europa.esig.dss.model.job.ParsingInfoRecord;
import eu.europa.esig.dss.model.lote.LoLoTEInfo;
import eu.europa.esig.dss.model.lote.LoTEInfo;
import eu.europa.esig.dss.model.lote.LoTEValidationJobSummary;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.lote.TrustedEntitiesCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.job.ValidationJob;
import eu.europa.esig.dss.validation.job.cache.CacheKey;
import eu.europa.esig.dss.validation.job.source.DocumentSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.stream.Collectors;

/**
 * The main user-interface for validation of Lists of trusted entities,
 * including business logic for download, parsing, validation tasks
 *
 */
public class LoTEValidationJob extends ValidationJob<LoTEInfo, LoLoTEInfo, LoTECacheAccessFactory> {

    private static final Logger LOG = LoggerFactory.getLogger(LoTEValidationJob.class);

    /**
     * The certificate source to be synchronized
     */
    private TrustedEntitiesCertificateSource trustedEntitiesCertificateSource;

    /**
     * Default constructor instantiating object with null configuration
     */
    public LoTEValidationJob() {
        super(new LoTECacheAccessFactory());
    }

    @Override
    protected LoTESource[] getDocumentSources() {
        return (LoTESource[]) super.getDocumentSources();
    }

    /**
     * Sets the additional List Sources
     *
     * @param loteSources {@link LoTESource}s
     */
    public void setLoTESources(LoTESource... loteSources) {
        setDocumentSources(loteSources);
    }

    @Override
    protected LoLoTESource[] getDocumentListSources() {
        return (LoLoTESource[]) super.getDocumentListSources();
    }

    /**
     * Sets the Lists of Lists of Trusted Entities Sources
     *
     * @param loloteSources {@link LoLoTESource}s
     */
    public void setLoLoTESources(LoLoTESource... loloteSources) {
        setDocumentListSources(loloteSources);
    }

    /**
     * Sets the TrustedListsCertificateSource to be filled with the job
     *
     * @param trustPropertiesCertificateSource
     *                                     the TrustedListsCertificateSource to fill
     *                                     with the job results
     */
    public void setTrustedEntitiesCertificateSource(TrustedEntitiesCertificateSource trustPropertiesCertificateSource) {
        this.trustedEntitiesCertificateSource = trustPropertiesCertificateSource;
    }

    /**
     * Returns validation job summary for all processed List of Lists or Lists
     *
     * @return {@link LoTEValidationJobSummary}
     */
    @Override
    public synchronized LoTEValidationJobSummary getSummary() {
        return (LoTEValidationJobSummary) super.getSummary();
    }

    @Override
    protected LoTEValidationJobSummaryBuilder getValidationJobSummaryBuilder() {
        return new LoTEValidationJobSummaryBuilder(getCacheAccessFactory().getReadOnlyCacheAccess(), getDocumentSources(), getDocumentListSources());
    }

    @Override
    protected Runnable getDocumentAnalysis(DocumentSource documentSource, DSSFileLoader dssFileLoader, CountDownLatch latch) {
        if (!(documentSource instanceof LoTESource)) {
            throw new IllegalArgumentException("The provided document source is not a LoTESource!");
        }
        LoTESource loteSource = (LoTESource) documentSource;
        final LoTECacheAccessByKey cacheAccess = getCacheAccessFactory().getCacheAccess(loteSource.getCacheKey());
        return new LoTEAnalysis(loteSource, cacheAccess, dssFileLoader, latch);
    }

    @Override
    protected Runnable getDocumentListAnalysis(DocumentSource documentSource, DSSFileLoader dssFileLoader, CountDownLatch latch) {
        if (!(documentSource instanceof LoLoTESource)) {
            throw new IllegalArgumentException("The provided document source is not a LoLoTESource!");
        }
        LoLoTESource loloteSource = (LoLoTESource) documentSource;
        final LoTECacheAccessByKey cacheAccess = getCacheAccessFactory().getCacheAccess(loloteSource.getCacheKey());
        return new LoLoTEAnalysis(loloteSource, cacheAccess, dssFileLoader, latch);
    }

    @Override
    protected List<? extends DocumentSource> extractOtherDocumentSources() {
        LoLoTESource[] loloteSources = getDocumentListSources();
        if (Utils.isArrayNotEmpty(loloteSources)) {
            List<LoLoTESource> loloteList = Arrays.asList(loloteSources);
            LoTESourceBuilder tlSourceBuilder = new LoTESourceBuilder(loloteList, extractLoTEParsingCache(loloteList));
            return tlSourceBuilder.build();
        }
        return Collections.emptyList();
    }

    private Map<CacheKey, LoTEParsingCacheDTO> extractLoTEParsingCache(List<LoLoTESource> loteSources) {
        final LoTEReadOnlyCacheAccess readOnlyCacheAccess = getCacheAccessFactory().getReadOnlyCacheAccess();
        return loteSources.stream().collect(Collectors.toMap(DocumentSource::getCacheKey, s -> readOnlyCacheAccess.getParsingInfoRecord(s.getCacheKey())));
    }

    @Override
    protected void synchronizeCertificateSources() {
        if (trustedEntitiesCertificateSource == null) {
            LOG.warn("No TrustedEntitiesCertificateSource to be synchronized");
            return;
        }

        LoTECertificateSourceSynchronizer synchronizer = new LoTECertificateSourceSynchronizer(
                getDocumentSources(), getDocumentListSources(), trustedEntitiesCertificateSource, getSynchronizationStrategy(),
                getCacheAccessFactory().getSynchronizerCacheAccess(), getCacheAccessFactory().getReadOnlyCacheAccess());
        synchronizer.sync();
    }

    @Override
    protected void handleDocumentChanges(Map<CacheKey, ParsingInfoRecord> oldParsingValues, Map<CacheKey, ParsingInfoRecord> newParsingValues) {
        final LoTEChangeApplier changeApplier = new LoTEChangeApplier(getCacheAccessFactory().getDocumentChangesCacheAccess(), oldParsingValues, newParsingValues);
        changeApplier.analyzeAndApply();
    }

}
