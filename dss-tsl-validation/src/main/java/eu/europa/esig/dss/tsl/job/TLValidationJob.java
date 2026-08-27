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
package eu.europa.esig.dss.tsl.job;

import eu.europa.esig.dss.alert.Alert;
import eu.europa.esig.dss.model.job.ParsingInfoRecord;
import eu.europa.esig.dss.model.tsl.LOTLInfo;
import eu.europa.esig.dss.model.tsl.TLInfo;
import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.model.tsl.TrustPropertiesCertificateSource;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.tsl.cache.access.TLCacheAccessByKey;
import eu.europa.esig.dss.tsl.cache.access.TLCacheAccessFactory;
import eu.europa.esig.dss.tsl.dto.TLParsingCacheDTO;
import eu.europa.esig.dss.tsl.runnable.LOTLAnalysis;
import eu.europa.esig.dss.tsl.runnable.LOTLWithPivotsAnalysis;
import eu.europa.esig.dss.tsl.runnable.TLAnalysis;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.tsl.summary.TLValidationJobSummaryBuilder;
import eu.europa.esig.dss.tsl.sync.TrustedListCertificateSourceSynchronizer;
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
 * The main class performing the TL/LOTL download / parsing / validation tasks
 *
 */
public class TLValidationJob extends ValidationJob<TLInfo, LOTLInfo, TLCacheAccessFactory> {

	private static final Logger LOG = LoggerFactory.getLogger(TLValidationJob.class);

	/**
	 * The certificate source to be synchronized
	 */
	private TrustPropertiesCertificateSource trustPropertiesCertificateSource;

	/**
	 * Default constructor instantiating object with null configuration
	 */
	public TLValidationJob() {
		super(new TLCacheAccessFactory());
	}

	@Override
	protected TLSource[] getDocumentSources() {
		return (TLSource[]) super.getDocumentSources();
	}

	/**
	 * Sets the additional TL Sources
	 *
	 * @param trustedListSources {@link TLSource}s
	 */
	public void setTrustedListSources(TLSource... trustedListSources) {
		setDocumentSources(trustedListSources);
	}

	@Override
	protected LOTLSource[] getDocumentListSources() {
		return (LOTLSource[]) super.getDocumentListSources();
	}

	/**
	 * Sets the LOTL Sources
	 *
	 * @param listOfTrustedListSources {@link LOTLSource}s
	 */
	public void setListOfTrustedListSources(LOTLSource... listOfTrustedListSources) {
		setDocumentListSources(listOfTrustedListSources);
	}
	
	/**
	 * Sets the TrustedListsCertificateSource to be filled with the job
	 * 
	 * @param trustPropertiesCertificateSource
	 *                                     the TrustedListsCertificateSource to fill
	 *                                     with the job results
	 */
	public void setTrustedListCertificateSource(TrustPropertiesCertificateSource trustPropertiesCertificateSource) {
		this.trustPropertiesCertificateSource = trustPropertiesCertificateSource;
	}
	
	/**
	 * Sets the LOTL alerts to be processed
	 * 
	 * @param lotlAlerts a list of {@link Alert}s
	 */
	public void setLOTLAlerts(List<Alert<LOTLInfo>> lotlAlerts) {
		setDocumentListAlerts(lotlAlerts);
	}
	
	/**
	 * Sets the TL alerts to be processed
	 * 
	 * @param tlAlerts a list of {@link Alert}s
	 */
	public void setTLAlerts(List<Alert<TLInfo>> tlAlerts) {
		setDocumentAlerts(tlAlerts);
	}

	/**
	 * Returns validation job summary for all processed LOTL / TLs
	 * @return {@link TLValidationJobSummary}
	 */
	@Override
	public synchronized TLValidationJobSummary getSummary() {
		return (TLValidationJobSummary) super.getSummary();
	}

	@Override
	protected TLValidationJobSummaryBuilder getValidationJobSummaryBuilder() {
		return new TLValidationJobSummaryBuilder(getCacheAccessFactory().getReadOnlyCacheAccess(), getDocumentSources(), getDocumentListSources());
	}

	@Override
	protected Runnable getDocumentAnalysis(DocumentSource documentSource, DSSFileLoader dssFileLoader, CountDownLatch latch) {
		if (!(documentSource instanceof TLSource)) {
			throw new IllegalArgumentException("The provided document source is not a TLSource!");
		}
		TLSource tlSource = (TLSource) documentSource;
		final TLCacheAccessByKey cacheAccess = getCacheAccessFactory().getCacheAccess(tlSource.getCacheKey());
		return new TLAnalysis(tlSource, cacheAccess, dssFileLoader, latch);
	}

	@Override
	protected Runnable getDocumentListAnalysis(DocumentSource documentSource, DSSFileLoader dssFileLoader, CountDownLatch latch) {
		if (!(documentSource instanceof LOTLSource)) {
			throw new IllegalArgumentException("The provided document source is not a LOTLSource!");
		}
		LOTLSource lotlSource = (LOTLSource) documentSource;
		final TLCacheAccessByKey cacheAccess = getCacheAccessFactory().getCacheAccess(documentSource.getCacheKey());
		if (lotlSource.isPivotSupport()) {
			return new LOTLWithPivotsAnalysis(lotlSource, cacheAccess, dssFileLoader, getCacheAccessFactory(), latch);
		} else {
			return new LOTLAnalysis(lotlSource, cacheAccess, dssFileLoader, latch);
		}
	}

	@Override
	protected List<? extends DocumentSource> extractOtherDocumentSources() {
		LOTLSource[] lotlSources = getDocumentListSources();
		if (Utils.isArrayNotEmpty(lotlSources)) {
			List<LOTLSource> lotlList = Arrays.asList(lotlSources);
			TLSourceBuilder tlSourceBuilder = new TLSourceBuilder(lotlList, extractTLParsingCache(lotlList));
			return tlSourceBuilder.build();
		}
		return Collections.emptyList();
	}

	private Map<CacheKey, TLParsingCacheDTO> extractTLParsingCache(List<LOTLSource> lotlSources) {
		final TLReadOnlyCacheAccess readOnlyCacheAccess = getCacheAccessFactory().getReadOnlyCacheAccess();
		return lotlSources.stream().collect(Collectors.toMap(DocumentSource::getCacheKey, s -> readOnlyCacheAccess.getParsingInfoRecord(s.getCacheKey())));
	}

	@Override
	protected void synchronizeCertificateSources() {
		if (trustPropertiesCertificateSource == null) {
			LOG.warn("No TrustedListCertificateSource to be synchronized");
			return;
		}

		TrustedListCertificateSourceSynchronizer synchronizer = new TrustedListCertificateSourceSynchronizer(
				getDocumentSources(), getDocumentListSources(), trustPropertiesCertificateSource, getSynchronizationStrategy(),
				getCacheAccessFactory().getSynchronizerCacheAccess(), getCacheAccessFactory().getReadOnlyCacheAccess());
		synchronizer.sync();
	}

	@Override
	protected void handleDocumentChanges(Map<CacheKey, ParsingInfoRecord> oldParsingValues, Map<CacheKey, ParsingInfoRecord> newParsingValues) {
		// Analyze introduced changes for TLs + adapt cache for TLs (EXPIRED)
		final LOTLChangeApplier lotlChangeApplier = new LOTLChangeApplier(getCacheAccessFactory().getDocumentChangesCacheAccess(), oldParsingValues, newParsingValues);
		lotlChangeApplier.analyzeAndApply();
	}

}
