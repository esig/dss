package eu.europa.esig.dss.tsl.summary;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.tsl.CertificatePivotStatus;
import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.OtherTSLPointer;
import eu.europa.esig.dss.spi.tsl.PivotInfo;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.access.ReadOnlyCacheAccess;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.utils.Utils;

public class ValidationJobSummaryBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(ValidationJobSummaryBuilder.class);

	/**
	 * A read-only access for the cache of the current Validation Job
	 */
	private final ReadOnlyCacheAccess readOnlyCacheAccess;

	/**
	 * List of TLSources to extract summary for
	 */
	private final TLSource[] tlSources;

	/**
	 * List of LOTLSource to extract summary for
	 */
	private final LOTLSource[] lotlSources;

	public ValidationJobSummaryBuilder(final ReadOnlyCacheAccess readOnlyCacheAccess, final TLSource[] tlSources, final LOTLSource[] lotlSources) {
		this.readOnlyCacheAccess = readOnlyCacheAccess;
		this.tlSources = tlSources;
		this.lotlSources = lotlSources;
	}

	public TLValidationJobSummary build() {

		final List<TLInfo> otherTLInfos = new ArrayList<TLInfo>();
		if (Utils.isArrayNotEmpty(tlSources)) {
			for (TLSource tlSource : tlSources) {
				otherTLInfos.add(buildTLInfo(tlSource));
			}
		}

		final List<LOTLInfo> lotlList = new ArrayList<LOTLInfo>();
		if (Utils.isArrayNotEmpty(lotlSources)) {

			for (LOTLSource lotlSource : lotlSources) {
				ParsingCacheDTO lotlParsingResult = readOnlyCacheAccess.getParsingCacheDTO(lotlSource.getCacheKey());

				LOTLInfo lotlInfo = buildLOTLInfo(lotlSource);

				List<TLInfo> tlInfos = new ArrayList<TLInfo>();
				List<TLSource> currentTLSources = extractTLSources(lotlParsingResult);
				for (TLSource tlSource : currentTLSources) {
					tlInfos.add(buildTLInfo(tlSource));
				}
				lotlInfo.setTlInfos(tlInfos);

				if (lotlSource.isPivotSupport()) {
					List<PivotInfo> pivotInfos = new LinkedList<PivotInfo>();

					List<CertificateToken> currentCertificates = getLOTLKeystoreCertificates(lotlSource);
					if (LOG.isDebugEnabled()) {
						LOG.debug("LOTL original keystore certs [Amount : {}] : {}", currentCertificates.size(), currentCertificates);
					}
					
					List<LOTLSource> pivotSources = extractPivotSources(lotlParsingResult);
					for (LOTLSource pivotSource : pivotSources) {
						List<CertificateToken> pivotCertificateTokens = getPivotCertificateTokens(pivotSource);
						Map<CertificateToken, CertificatePivotStatus> certificateChangesMap = getCertificateChangesMap(
								pivotCertificateTokens, currentCertificates);
						pivotInfos.add(buildPivotInfo(pivotSource, certificateChangesMap));
						currentCertificates = pivotCertificateTokens;
						if (LOG.isDebugEnabled()) {
							LOG.debug("Pivot [{}] certificate source [Amount : {}] : {}", pivotSource.getUrl(), currentCertificates.size(), currentCertificates);
						}
						
					}
					lotlInfo.setPivotInfos(pivotInfos);
					
				} else {
					lotlInfo.setPivotInfos(Collections.emptyList());
				}

				lotlList.add(lotlInfo);
			}
		}

		return new TLValidationJobSummary(lotlList, otherTLInfos);
	}

	private LOTLInfo buildLOTLInfo(LOTLSource lotlSource) {
		CacheKey cacheKey = lotlSource.getCacheKey();
		return new LOTLInfo(readOnlyCacheAccess.getDownloadCacheDTO(cacheKey), readOnlyCacheAccess.getParsingCacheDTO(cacheKey),
				readOnlyCacheAccess.getValidationCacheDTO(cacheKey), lotlSource.getUrl());
	}

	private TLInfo buildTLInfo(TLSource tlSource) {
		CacheKey cacheKey = tlSource.getCacheKey();
		return new TLInfo(readOnlyCacheAccess.getDownloadCacheDTO(cacheKey), readOnlyCacheAccess.getParsingCacheDTO(cacheKey),
				readOnlyCacheAccess.getValidationCacheDTO(cacheKey), tlSource.getUrl());
	}

	private PivotInfo buildPivotInfo(LOTLSource pivotSource, Map<CertificateToken, CertificatePivotStatus> certificateChangesMap) {
		CacheKey cacheKey = pivotSource.getCacheKey();
		return new PivotInfo(readOnlyCacheAccess.getDownloadCacheDTO(cacheKey), readOnlyCacheAccess.getParsingCacheDTO(cacheKey),
				readOnlyCacheAccess.getValidationCacheDTO(cacheKey), pivotSource.getUrl(), certificateChangesMap);
	}

	private List<TLSource> extractTLSources(ParsingCacheDTO lotlParsingResult) {
		List<TLSource> result = new ArrayList<TLSource>();
		if (lotlParsingResult != null && lotlParsingResult.isResultExist()) {
			List<OtherTSLPointer> tlPointers = lotlParsingResult.getTlOtherPointers();
			for (OtherTSLPointer otherTSLPointerDTO : tlPointers) {
				TLSource tlSource = new TLSource();
				tlSource.setUrl(otherTSLPointerDTO.getLocation());
				result.add(tlSource);
			}
		}
		return result;
	}
	
	private List<CertificateToken> getLOTLKeystoreCertificates(LOTLSource lotlSource) {
		CertificateSource certificateSource = lotlSource.getCertificateSource();
		if (certificateSource != null) {
			return certificateSource.getCertificates();
		} else {
			LOG.warn("Certificate source is not defined for the LOTL with URL [{}]", lotlSource.getUrl());
			return Collections.emptyList();
		}
	}
	
	private List<LOTLSource> extractPivotSources(ParsingCacheDTO lotlParsingResult) {
		List<LOTLSource> result = new LinkedList<LOTLSource>();
		if (lotlParsingResult != null && lotlParsingResult.isResultExist()) {
			List<String> pivotUrls = lotlParsingResult.getPivotUrls();
			for (String pivotUrl : pivotUrls) {
				LOTLSource pivotSource = new LOTLSource();
				pivotSource.setUrl(pivotUrl);
				result.add(pivotSource);
			}
		}
		Collections.reverse(result);
		return result;
	}
	
	private List<CertificateToken> getPivotCertificateTokens(LOTLSource pivotSource) {
		CacheKey cacheKey = pivotSource.getCacheKey();
		ParsingCacheDTO parsingCacheDTO = readOnlyCacheAccess.getParsingCacheDTO(cacheKey);
		List<OtherTSLPointer> lotlOtherPointers = parsingCacheDTO.getLotlOtherPointers();
		int lotlOtherPointersAmount = Utils.isCollectionNotEmpty(lotlOtherPointers) ? lotlOtherPointers.size() : 0;
		if (lotlOtherPointersAmount == 1) {
			return lotlOtherPointers.get(0).getCertificates();
		} else {
			LOG.debug("Pivot certificates were not extracted. Nb of OtherTSLPointers is [{}]", lotlOtherPointersAmount);
			return Collections.emptyList();
		}
	}
	
	private Map<CertificateToken, CertificatePivotStatus> getCertificateChangesMap(List<CertificateToken> pivotSourceCertificates, 
			List<CertificateToken> currentCertificates) {
		Map<CertificateToken, CertificatePivotStatus> certificateChangesMap = new LinkedHashMap<CertificateToken, CertificatePivotStatus>();
		
		List<CertificateToken> commonCertificates = pivotSourceCertificates.stream().filter(cert -> { 
				return currentCertificates.contains(cert); 
			}).collect(Collectors.toList());
		
		// added certificates
		for (CertificateToken certificateToken : pivotSourceCertificates) {
			if (!commonCertificates.contains(certificateToken)) {
				certificateChangesMap.put(certificateToken, CertificatePivotStatus.ADDED);
			}
		}
		
		// common certificates
		for (CertificateToken certificateToken : commonCertificates) {
			certificateChangesMap.put(certificateToken, CertificatePivotStatus.NOT_CHANGED);
		}
		
		// removed certificates
		for (CertificateToken certificateToken : currentCertificates) {
			if (!commonCertificates.contains(certificateToken)) {
				certificateChangesMap.put(certificateToken, CertificatePivotStatus.REMOVED);
			}
		}
		
		return certificateChangesMap;
	}

}
