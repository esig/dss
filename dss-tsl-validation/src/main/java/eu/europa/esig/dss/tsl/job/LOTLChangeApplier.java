package eu.europa.esig.dss.tsl.job;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.tsl.OtherTSLPointer;
import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.access.TLChangesCacheAccess;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.utils.Utils;

public class LOTLChangeApplier {

	private static final Logger LOG = LoggerFactory.getLogger(LOTLChangeApplier.class);

	private final TLChangesCacheAccess cacheAccess;

	private final Map<CacheKey, ParsingCacheDTO> oldValues;
	private final Map<CacheKey, ParsingCacheDTO> newValues;

	public LOTLChangeApplier(final TLChangesCacheAccess cacheAccess, 
			final Map<CacheKey, ParsingCacheDTO> oldValues, final Map<CacheKey, ParsingCacheDTO> newValues) {
		this.cacheAccess = cacheAccess;
		this.oldValues = oldValues;
		this.newValues = newValues;
	}

	public void analyzeAndApply() {
		for (Entry<CacheKey, ParsingCacheDTO> oldEntry : oldValues.entrySet()) {
			Map<String, List<CertificateToken>> oldUrlCerts = getTLPointers(oldEntry.getValue());
			Map<String, List<CertificateToken>> newUrlCerts = getTLPointers(newValues.get(oldEntry.getKey()));

			detectUrlChanges(oldUrlCerts, newUrlCerts);
			detectSigCertsChanges(oldUrlCerts, newUrlCerts);
		}
	}

	private Map<String, List<CertificateToken>> getTLPointers(ParsingCacheDTO parsingResult) {
		List<OtherTSLPointer> tlOtherPointers = parsingResult.getTlOtherPointers();
		if (Utils.isCollectionNotEmpty(tlOtherPointers)) {
			return tlOtherPointers.stream().collect(Collectors.toMap(OtherTSLPointer::getLocation, s -> s.getCertificates()));
		}
		return Collections.emptyMap();
	}

	private void detectUrlChanges(Map<String, List<CertificateToken>> oldUrlCerts, Map<String, List<CertificateToken>> newUrlCerts) {
		for (String oldUrl : oldUrlCerts.keySet()) {
			if (!newUrlCerts.containsKey(oldUrl)) {
				LOG.info("TL with URL '{}' is not used anymore (replaced URL in the LOTL)", oldUrl);
				cacheAccess.toBeDeleted(new CacheKey(oldUrl));
			}
		}
	}

	private void detectSigCertsChanges(Map<String, List<CertificateToken>> oldUrlCerts, Map<String, List<CertificateToken>> newUrlCerts) {
		for (Entry<String, List<CertificateToken>> newEntry : newUrlCerts.entrySet()) {
			String newUrl = newEntry.getKey();
			List<CertificateToken> oldCerts = oldUrlCerts.get(newUrl);
			List<CertificateToken> newCerts = newEntry.getValue();
			if (oldCerts != null && !oldCerts.equals(newCerts)) {
				LOG.info("Signing certificates change detected for TL with URL '{}'", newUrl);
				cacheAccess.expireSignatureValidation(new CacheKey(newUrl));
			}
		}
	}

}
