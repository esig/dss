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
package eu.europa.esig.dss.tsl.sync;

import eu.europa.esig.dss.model.timedependent.TimeDependentValues;
import eu.europa.esig.dss.model.tsl.CertificateTrustTime;
import eu.europa.esig.dss.model.tsl.LOTLInfo;
import eu.europa.esig.dss.model.tsl.ParsingInfoRecord;
import eu.europa.esig.dss.model.tsl.PivotInfo;
import eu.europa.esig.dss.model.tsl.TLInfo;
import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.model.tsl.TrustProperties;
import eu.europa.esig.dss.model.tsl.TrustPropertiesCertificateSource;
import eu.europa.esig.dss.model.tsl.TrustService;
import eu.europa.esig.dss.model.tsl.TrustServiceProvider;
import eu.europa.esig.dss.model.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.access.SynchronizerCacheAccess;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.tsl.summary.ValidationJobSummaryBuilder;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.function.Predicate;

/**
 * Loads trusted certificate source
 */
public class TrustedListCertificateSourceSynchronizer {

	private static final Logger LOG = LoggerFactory.getLogger(TrustedListCertificateSourceSynchronizer.class);

	/**
	 * List of TLSources to extract summary for
	 */
	private final TLSource[] tlSources;

	/**
	 * List of LOTLSource to extract summary for
	 */
	private final LOTLSource[] lotlSources;

	/**
	 * The strategy to follow for the certificate synchronization
	 */
	private final SynchronizationStrategy synchronizationStrategy;

	/**
	 * The certificate source to be synchronized
	 */
	private final TrustPropertiesCertificateSource certificateSource;

	/**
	 * The cache access
	 */
	private final SynchronizerCacheAccess cacheAccess;

	/**
	 * Default constructor
	 *
	 * @param tlSources {@link TLSource}s
	 * @param lotlSources {@link LOTLSource}s
	 * @param certificateSource {@link TrustPropertiesCertificateSource}
	 * @param synchronizationStrategy {@link SynchronizationStrategy}
	 * @param cacheAccess {@link SynchronizerCacheAccess}
	 */
	public TrustedListCertificateSourceSynchronizer(TLSource[] tlSources, LOTLSource[] lotlSources,
			TrustPropertiesCertificateSource certificateSource, SynchronizationStrategy synchronizationStrategy,
			SynchronizerCacheAccess cacheAccess) {
		this.tlSources = tlSources;
		this.lotlSources = lotlSources;
		this.synchronizationStrategy = synchronizationStrategy;
		this.certificateSource = certificateSource;
		this.cacheAccess = cacheAccess;
	}

	/**
	 * Synchronizes the trusted certificate source based on the validation job processing result
	 */
	public void sync() {
		try {
			ValidationJobSummaryBuilder summaryBuilder = new ValidationJobSummaryBuilder(cacheAccess, tlSources, lotlSources);

			TLValidationJobSummary summary = summaryBuilder.build();
			if (isCertificateSyncNeeded(summary)) {
				synchronizeCertificates(summary);
			}
			syncCache(summary);

			// re-build summary after synchronization
			summary = summaryBuilder.build();
			certificateSource.setSummary(summary);

		} catch (Exception e) {
			LOG.error("Unable to synchronize the TrustedListsCertificateSource", e);
		}
	}

	private boolean isCertificateSyncNeeded(TLValidationJobSummary summary) {
		for (LOTLInfo lotlInfo : summary.getLOTLInfos()) {
			if (isTLParsingDesyncOrError(lotlInfo) || isTLParsingDesyncOrError(lotlInfo.getTLInfos())) {
				return true;
			}
		}
		return isTLParsingDesyncOrError(summary.getOtherTLInfos());
	}

	private boolean isTLParsingDesyncOrError(List<TLInfo> tlInfos) {
		return tlInfos.stream().anyMatch(this::isTLParsingDesyncOrError);
	}

	private boolean isTLParsingDesyncOrError(TLInfo tlInfo) {
		ParsingInfoRecord parsingCacheInfo = tlInfo.getParsingCacheInfo();
		return parsingCacheInfo == null || parsingCacheInfo.isDesynchronized() || parsingCacheInfo.isError();
	}

	private void synchronizeCertificates(TLValidationJobSummary summary) {
		final Map<CertificateToken, List<TrustProperties>> trustPropertiesByCerts = new WeakHashMap<>();
		final Map<CertificateToken, List<CertificateTrustTime>> trustTimeByCerts = new WeakHashMap<>();
		for (LOTLInfo lotlInfo : summary.getLOTLInfos()) {
			if (synchronizationStrategy.canBeSynchronized(lotlInfo)) {
				addCertificatesFromTLs(trustPropertiesByCerts, trustTimeByCerts, lotlInfo.getTLInfos(), lotlInfo);
			} else {
				LOG.warn("Certificate synchronization is skipped for LOTL '{}' and its TLs", lotlInfo.getUrl());
			}
		}
		addCertificatesFromTLs(trustPropertiesByCerts, trustTimeByCerts, summary.getOtherTLInfos(), null);
		certificateSource.setTrustPropertiesByCertificates(trustPropertiesByCerts);
		certificateSource.setTrustTimeByCertificates(trustTimeByCerts);
	}

	private void addCertificatesFromTLs(final Map<CertificateToken, List<TrustProperties>> trustPropertiesByCerts,
										final Map<CertificateToken, List<CertificateTrustTime>> trustTimeByCerts,
										final List<TLInfo> tlInfos, final LOTLInfo relatedLOTL) {

		for (final TLInfo tlInfo : tlInfos) {
			if (synchronizationStrategy.canBeSynchronized(tlInfo)) {
				ParsingInfoRecord parsingCacheInfo = tlInfo.getParsingCacheInfo();
				if (parsingCacheInfo == null || !parsingCacheInfo.isResultExist()) {
					LOG.warn("No Parsing result for TLInfo with url [{}]", tlInfo.getUrl());
				} else {
					final List<TrustServiceProvider> trustServiceProviders = parsingCacheInfo.getTrustServiceProviders();
					if (Utils.isCollectionNotEmpty(trustServiceProviders)) {
						final Predicate<TrustServiceStatusAndInformationExtensions> trustAnchorValidityPredicate =
								getTrustAnchorValidityPredicate(tlInfo, relatedLOTL);
						for (TrustServiceProvider original : trustServiceProviders) {
							TrustServiceProvider detached = getDetached(original);
							for (TrustService trustService : original.getServices()) {
								TimeDependentValues<TrustServiceStatusAndInformationExtensions> statusAndInformationExtensions =
										trustService.getStatusAndInformationExtensions();
								TrustProperties trustProperties = getTrustProperties(
										relatedLOTL, tlInfo, detached, statusAndInformationExtensions);
								List<CertificateTrustTime> certificateTrustTimes = getCertificateTrustTimes(statusAndInformationExtensions, trustAnchorValidityPredicate);
								for (CertificateToken certificate : trustService.getCertificates()) {
									addCertificate(trustPropertiesByCerts, trustTimeByCerts, certificate, trustProperties, certificateTrustTimes);
								}
							}
						}
					}
				}
			} else {
				LOG.warn("Certificate synchronization is skipped for TL '{}'", tlInfo.getUrl());
			}
		}
	}

	private void addCertificate(final Map<CertificateToken, List<TrustProperties>> trustPropertiesByCerts,
								final Map<CertificateToken, List<CertificateTrustTime>> trustTimeByCerts,
								CertificateToken certificate, TrustProperties trustProperties, List<CertificateTrustTime> certificateTrustTimes) {
		List<TrustProperties> trustPropertiesList = trustPropertiesByCerts.computeIfAbsent(certificate, k -> new ArrayList<>());
		if (!trustPropertiesList.contains(trustProperties)) {
			trustPropertiesList.add(trustProperties);
		}
		List<CertificateTrustTime> certificateTrustTimeList = trustTimeByCerts.computeIfAbsent(certificate, k -> new ArrayList<>());
		for (CertificateTrustTime certificateTrustTime : certificateTrustTimes) {
			if (!certificateTrustTimeList.contains(certificateTrustTime)) {
				certificateTrustTimeList.add(certificateTrustTime);
			}
		}
	}

	private TrustServiceProvider getDetached(TrustServiceProvider original) {
		TrustServiceProviderBuilder builder = new TrustServiceProviderBuilder(original);
		builder.setServices(Collections.emptyList());
		return builder.build();
	}

	private void syncCache(TLValidationJobSummary summary) {
		for (LOTLInfo lotlInfo : summary.getLOTLInfos()) {
			syncTLInfosCache(lotlInfo.getTLInfos());
			syncPivotsCache(lotlInfo.getPivotInfos());
			cacheAccess.sync(new CacheKey(lotlInfo.getUrl()));
		}
		syncTLInfosCache(summary.getOtherTLInfos());
	}

	private void syncPivotsCache(List<PivotInfo> pivotInfos) {
		for (PivotInfo pivotInfo : pivotInfos) {
			cacheAccess.sync(new CacheKey(pivotInfo.getUrl()));
		}
	}

	private void syncTLInfosCache(List<TLInfo> tlInfos) {
		for (TLInfo tlInfo : tlInfos) {
			cacheAccess.sync(new CacheKey(tlInfo.getUrl()));
		}
	}

	private TrustProperties getTrustProperties(LOTLInfo relatedLOTL, TLInfo tlInfo, TrustServiceProvider detached,
			TimeDependentValues<TrustServiceStatusAndInformationExtensions> statusAndInformationExtensions) {
		if (relatedLOTL == null) {
			return new TrustProperties(tlInfo, detached, statusAndInformationExtensions);
		}
		return new TrustProperties(relatedLOTL, tlInfo, detached, statusAndInformationExtensions);
	}

	private List<CertificateTrustTime> getCertificateTrustTimes(
			TimeDependentValues<TrustServiceStatusAndInformationExtensions> statusAndInformationExtensions,
			Predicate<TrustServiceStatusAndInformationExtensions> trustAnchorValidityPredicate) {
		if (trustAnchorValidityPredicate == null) {
			// return empty instance (always valid), when no predicate is defined
			return Collections.singletonList(new CertificateTrustTime(true));
		}

		final List<CertificateTrustTime> result = new ArrayList<>();
        for (TrustServiceStatusAndInformationExtensions trustServiceStatusAndInformation : statusAndInformationExtensions) {
            // TODO : add handling of MRA ?
            if (trustAnchorValidityPredicate.test(trustServiceStatusAndInformation)) {
				result.add(new CertificateTrustTime(trustServiceStatusAndInformation.getStartDate(), trustServiceStatusAndInformation.getEndDate()));
            } else {
				result.add(new CertificateTrustTime(false)); // not trusted
			}
        }
		return result;
	}

	private Predicate<TrustServiceStatusAndInformationExtensions> getTrustAnchorValidityPredicate(TLInfo tlInfo, LOTLInfo relatedLOTLInfo) {
		TLSource tlSource = getRelatedTLSource(tlInfo, relatedLOTLInfo);
		if (tlSource != null) {
			return tlSource.getTrustAnchorValidityPredicate();
		}
		return null;
	}

	private TLSource getRelatedTLSource(TLInfo tlInfo, LOTLInfo relatedLOTLInfo) {
		if (relatedLOTLInfo != null) {
			for (LOTLSource lotlSource : lotlSources) {
				if (lotlSource.getUrl().equals(relatedLOTLInfo.getUrl())) {
					return lotlSource;
				}
			}
		}
		for (TLSource tlSource : tlSources) {
			if (tlSource.getUrl().equals(tlInfo.getUrl())) {
				return tlSource;
			}
		}
		return null;
	}

}
