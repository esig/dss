package eu.europa.esig.dss.tsl.utils;

import java.util.List;
import java.util.stream.Collectors;

import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.source.LOTLSource;

public final class TLValidationUtils {
	
	public static List<CacheKey> getCacheKeyList(List<LOTLSource> lotlSources) {
		return lotlSources.stream().map(LOTLSource::getCacheKey).collect(Collectors.toList());
	}

}
