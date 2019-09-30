package eu.europa.esig.dss.tsl.summary;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.PivotInfo;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.tsl.dto.OtherTSLPointer;
import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.ReadOnlyCacheAccess;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.utils.Utils;

public class ValidationJobSummaryBuilder {

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

	public ValidationJobSummary build() {

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
					List<PivotInfo> pivotInfos = new ArrayList<PivotInfo>();
					List<LOTLSource> pivotSources = extractPivotSources(lotlParsingResult);
					for (LOTLSource pivotSource : pivotSources) {
						pivotInfos.add(buildPivotInfo(pivotSource));
					}
					lotlInfo.setPivotInfos(pivotInfos);
				} else {
					lotlInfo.setPivotInfos(Collections.emptyList());
				}

				lotlList.add(lotlInfo);
			}
		}

		return new ValidationJobSummary(lotlList, otherTLInfos);
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

	private PivotInfo buildPivotInfo(LOTLSource pivotSource) {
		CacheKey cacheKey = pivotSource.getCacheKey();
		return new PivotInfo(readOnlyCacheAccess.getDownloadCacheDTO(cacheKey), readOnlyCacheAccess.getParsingCacheDTO(cacheKey),
				readOnlyCacheAccess.getValidationCacheDTO(cacheKey), pivotSource.getUrl());
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

	private List<LOTLSource> extractPivotSources(ParsingCacheDTO lotlParsingResult) {
		List<LOTLSource> result = new ArrayList<LOTLSource>();
		if (lotlParsingResult != null && lotlParsingResult.isResultExist()) {
			List<String> pivotUrls = lotlParsingResult.getPivotUrls();
			for (String pivotUrl : pivotUrls) {
				LOTLSource pivotSource = new LOTLSource();
				pivotSource.setUrl(pivotUrl);
				result.add(pivotSource);
			}
		}
		return result;
	}

}
