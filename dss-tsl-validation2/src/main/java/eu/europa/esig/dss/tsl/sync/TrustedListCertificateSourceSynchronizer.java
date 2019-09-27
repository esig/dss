package eu.europa.esig.dss.tsl.sync;

import java.util.List;

import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.PivotInfo;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.tsl.dto.info.ParsingInfoRecord;
import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.SynchronizerCacheAccess;
import eu.europa.esig.dss.tsl.summary.ValidationJobSummary;

public class TrustedListCertificateSourceSynchronizer {

	private final ValidationJobSummary originalSummary;
	private final TrustedListsCertificateSource certificateSource;
	private final SynchronizerCacheAccess cacheAccess;

	public TrustedListCertificateSourceSynchronizer(ValidationJobSummary originalSummary, TrustedListsCertificateSource certificateSource,
			SynchronizerCacheAccess cacheAccess) {
		this.originalSummary = originalSummary;
		this.certificateSource = certificateSource;
		this.cacheAccess = cacheAccess;
	}

	public void sync() {
		try {
			if (isCertificateSyncNeeded()) {

			}

			syncCache();

//			certificateSource.setLOTLInfos(lotlInfos);
//			certificateSource.setOtherTlInfos(tlInfos);
		} catch (Exception e) {
			// TODO: handle exception
		}
	}

	private boolean isCertificateSyncNeeded() {
		for (LOTLInfo lotlInfo : originalSummary.getLOTLInfos()) {
			if (isTLParsingDesyncOrError(lotlInfo.getTLInfos())) {
				return true;
			}
		}
		return isTLParsingDesyncOrError(originalSummary.getOtherTLInfos());
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

	private void synchronizeCertificates() {
		for (LOTLInfo lotlInfo : originalSummary.getLOTLInfos()) {
			addCertificatesFromTLs(lotlInfo.getTLInfos());
		}
		addCertificatesFromTLs(originalSummary.getOtherTLInfos());
	}

	private void addCertificatesFromTLs(List<TLInfo> tlInfos) {
		for (TLInfo tlInfo : tlInfos) {
			
//			certificateSource.addCertificate(certificate, serviceInfos);
		}
	}

	private void syncCache() {
		for (LOTLInfo lotlInfo : originalSummary.getLOTLInfos()) {
			syncTLInfosCache(lotlInfo.getTLInfos());
			syncPivotsCache(lotlInfo.getPivotInfos());
			cacheAccess.sync(new CacheKey(lotlInfo.getUrl()));
		}
		syncTLInfosCache(originalSummary.getOtherTLInfos());
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
