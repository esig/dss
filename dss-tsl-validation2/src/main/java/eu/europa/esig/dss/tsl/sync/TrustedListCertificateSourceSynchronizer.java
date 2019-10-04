package eu.europa.esig.dss.tsl.sync;

import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.PivotInfo;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.spi.tsl.TrustProperties;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.tsl.dto.TrustService;
import eu.europa.esig.dss.spi.tsl.dto.TrustServiceProvider;
import eu.europa.esig.dss.spi.tsl.dto.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.spi.tsl.dto.builder.TrustServiceProviderBuilder;
import eu.europa.esig.dss.spi.tsl.dto.info.ParsingInfoRecord;
import eu.europa.esig.dss.spi.util.TimeDependentValues;
import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.access.SynchronizerCacheAccess;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.tsl.summary.ValidationJobSummaryBuilder;

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
	 * The certificate source to be synchronized
	 */
	private final TrustedListsCertificateSource certificateSource;

	/**
	 * The cache access
	 */
	private final SynchronizerCacheAccess cacheAccess;

	public TrustedListCertificateSourceSynchronizer(TLSource[] tlSources, LOTLSource[] lotlSources, TrustedListsCertificateSource certificateSource,
			SynchronizerCacheAccess cacheAccess) {
		this.tlSources = tlSources;
		this.lotlSources = lotlSources;
		this.certificateSource = certificateSource;
		this.cacheAccess = cacheAccess;
	}

	public void sync() {
		try {

			ValidationJobSummaryBuilder summaryBuilder = new ValidationJobSummaryBuilder(cacheAccess, tlSources, lotlSources);
			TLValidationJobSummary summary = summaryBuilder.build();

			if (isCertificateSyncNeeded(summary)) {
				synchronizeCertificates(summary);
			}

			syncCache(summary);

			certificateSource.setSummary(summaryBuilder.build());
		} catch (Exception e) {
			LOG.error("Unable to synchronize the TrustedListsCertificateSource", e);
		}
	}

	private boolean isCertificateSyncNeeded(TLValidationJobSummary summary) {
		for (LOTLInfo lotlInfo : summary.getLOTLInfos()) {
			if (isTLParsingDesyncOrError(lotlInfo.getTLInfos())) {
				return true;
			}
		}
		return isTLParsingDesyncOrError(summary.getOtherTLInfos());
	}

	private boolean isTLParsingDesyncOrError(List<TLInfo> tlInfos) {
		for (TLInfo tlInfo : tlInfos) {
			ParsingInfoRecord parsingCacheInfo = tlInfo.getParsingCacheInfo();
			if (parsingCacheInfo.isDesynchronized() || parsingCacheInfo.isError()) {
				return true;
			}
		}
		return false;
	}

	private void synchronizeCertificates(TLValidationJobSummary summary) {
		certificateSource.reinit();
		for (LOTLInfo lotlInfo : summary.getLOTLInfos()) {
			addCertificatesFromTLs(lotlInfo.getTLInfos(), lotlInfo);
		}
		addCertificatesFromTLs(summary.getOtherTLInfos(), null);
	}

	private void addCertificatesFromTLs(List<TLInfo> tlInfos, LOTLInfo relatedLOTL) {
		for (TLInfo tlInfo : tlInfos) {
			String tlUrl = tlInfo.getUrl();
			ParsingInfoRecord parsingCacheInfo = tlInfo.getParsingCacheInfo();
			if (parsingCacheInfo.isError()) {
				continue;
			}
			List<TrustServiceProvider> trustServiceProviders = parsingCacheInfo.getTrustServiceProviders();
			for (TrustServiceProvider original : trustServiceProviders) {
				TrustServiceProvider detached = getDetached(original);
				for (TrustService trustService : original.getServices()) {

					TimeDependentValues<TrustServiceStatusAndInformationExtensions> statusAndInformationExtensions = trustService
							.getStatusAndInformationExtensions();

					for (CertificateToken certificate : trustService.getCertificates()) {
						if (relatedLOTL == null) {
						certificateSource.addCertificate(certificate, new TrustProperties(tlUrl, detached, statusAndInformationExtensions));
						} else {
							certificateSource.addCertificate(certificate,
									new TrustProperties(relatedLOTL.getUrl(), tlUrl, detached, statusAndInformationExtensions));
						}
					}
				}
			}
		}
	}

	private TrustServiceProvider getDetached(TrustServiceProvider original) {
		TrustServiceProviderBuilder builder = new TrustServiceProviderBuilder(original);
		builder.setServices(Collections.emptyList());
		TrustServiceProvider detached = builder.build();
		return detached;
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

}
