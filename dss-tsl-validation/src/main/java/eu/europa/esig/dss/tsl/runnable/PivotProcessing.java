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
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.model.tsl.OtherTSLPointer;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.tsl.cache.access.TLCacheAccessByKey;
import eu.europa.esig.dss.tsl.download.XmlDownloadTask;
import eu.europa.esig.dss.tsl.dto.TLParsingCacheDTO;
import eu.europa.esig.dss.tsl.parsing.LOTLParsingTask;
import eu.europa.esig.dss.tsl.parsing.ParsingUtils;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.validation.TLValidatorTask;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.job.cache.access.AbstractCacheAccessByKey;
import eu.europa.esig.dss.validation.job.download.DownloadTask;
import eu.europa.esig.dss.validation.job.runnable.AbstractAnalysis;
import eu.europa.esig.dss.validation.job.validation.ValidationTask;

import java.util.List;
import java.util.concurrent.Callable;

/**
 * Processes a pivot analysis
 */
public class PivotProcessing extends AbstractAnalysis implements Callable<PivotProcessingResult> {

	/** The cache access of the LOTL */
	private final TLCacheAccessByKey lotlCacheAccess;

	/** List of other pivots, to be updated in case of current pivot update */
	private final List<TLCacheAccessByKey> preceedingPivotCacheAccessByKeyList;

	/**
	 * Default constructor
	 *
	 * @param pivotSource {@link LOTLSource} pivot source
	 * @param pivotCacheAccess {@link AbstractCacheAccessByKey} cache access of the current Pivot to process
	 * @param lotlCacheAccess {@link AbstractCacheAccessByKey} cache access of the corresponding LOTL
	 * @param preceedingPivotCacheAccessByKeyList a list of {@link AbstractCacheAccessByKey} to access other pivots
	 * @param dssFileLoader {@link DSSFileLoader}
	 * @deprecated since DSS 6.6. Please use
	 *             {@link PivotProcessing(LOTLSource, TLCacheAccessByKey, TLCacheAccessByKey, List<TLCacheAccessByKey>, DSSFileLoader, ValidationPolicy)}
	 */
	@Deprecated
	public PivotProcessing(final LOTLSource pivotSource, final TLCacheAccessByKey pivotCacheAccess,
	                       final TLCacheAccessByKey lotlCacheAccess, List<TLCacheAccessByKey> preceedingPivotCacheAccessByKeyList,
	                       final DSSFileLoader dssFileLoader) {
		this(pivotSource, pivotCacheAccess, lotlCacheAccess, preceedingPivotCacheAccessByKeyList, dssFileLoader, null);
	}

	/**
	 * Default constructor
	 *
	 * @param pivotSource {@link LOTLSource} pivot source
	 * @param pivotCacheAccess {@link AbstractCacheAccessByKey} cache access of the current Pivot to process
	 * @param lotlCacheAccess {@link AbstractCacheAccessByKey} cache access of the corresponding LOTL
	 * @param preceedingPivotCacheAccessByKeyList a list of {@link AbstractCacheAccessByKey} to access other pivots
	 * @param dssFileLoader {@link DSSFileLoader}
	 */
	public PivotProcessing(final LOTLSource pivotSource, final TLCacheAccessByKey pivotCacheAccess,
						   final TLCacheAccessByKey lotlCacheAccess, final List<TLCacheAccessByKey> preceedingPivotCacheAccessByKeyList,
						   final DSSFileLoader dssFileLoader, ValidationPolicy validationPolicy) {
		super(pivotSource, pivotCacheAccess, dssFileLoader, validationPolicy);
		this.lotlCacheAccess = lotlCacheAccess;
		this.preceedingPivotCacheAccessByKeyList = preceedingPivotCacheAccessByKeyList;
	}

	@Override
	public PivotProcessingResult call() throws Exception {
		DSSDocument pivot = download(getSource().getUrl());
		if (pivot != null) {
			parsing(pivot);

			TLCacheAccessByKey cacheAccessByKey = (TLCacheAccessByKey) getCacheAccessByKey();
			TLParsingCacheDTO parsingResult = cacheAccessByKey.getParsingReadOnlyResult();
			OtherTSLPointer xmlLotlPointer = ParsingUtils.getXMLLOTLPointer(parsingResult);
			if (xmlLotlPointer != null) {
				return new PivotProcessingResult(pivot, ParsingUtils.getLOTLAnnouncedCertificateSource(xmlLotlPointer), xmlLotlPointer.getTSLLocation());
			}
		}
		return null;
	}

	@Override
	protected DownloadTask getDownloadTask(DSSFileLoader dssFileLoader, String url) {
		return new XmlDownloadTask(dssFileLoader, url);
	}

	@Override
	protected LOTLParsingTask getParsingTask(DSSDocument document) {
		return new LOTLParsingTask(document, (LOTLSource) getSource());
	}

	@Override
	protected ValidationTask getValidationTask(DSSDocument document, CertificateSource certificateSource) {
		return new TLValidatorTask(document, certificateSource, getValidationPolicy());
	}

	@Override
	protected void expireCache() {
		super.expireCache();
		lotlCacheAccess.expireValidation(); // ensure LOTL will be updated in case of pivot refresh
		// expire Pivots before the current
		if (Utils.isCollectionNotEmpty(preceedingPivotCacheAccessByKeyList)) {
			for (AbstractCacheAccessByKey pivotCacheAccessByKey : preceedingPivotCacheAccessByKeyList) {
				pivotCacheAccessByKey.expireValidation();
			}
		}
	}

}
