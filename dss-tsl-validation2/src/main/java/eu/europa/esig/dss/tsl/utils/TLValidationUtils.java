package eu.europa.esig.dss.tsl.utils;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.dto.OtherTSLPointerDTO;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.utils.Utils;

public final class TLValidationUtils {
	
	public static List<CacheKey> getCacheKeyList(List<LOTLSource> lotlSources) {
		return lotlSources.stream().map(LOTLSource::getCacheKey).collect(Collectors.toList());
	}
	
	public static List<CertificateToken> getLOTLAnnouncedSigningCertificates(List<OtherTSLPointerDTO> loltPointers) {
		if (Utils.isCollectionNotEmpty(loltPointers)) {
			return loltPointers.get(0).getCertificates();
		}
		return Collections.emptyList();
	}

}
