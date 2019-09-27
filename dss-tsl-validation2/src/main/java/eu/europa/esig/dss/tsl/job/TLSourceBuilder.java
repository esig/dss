package eu.europa.esig.dss.tsl.job;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.tsl.dto.OtherTSLPointer;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;

public class TLSourceBuilder {

	private final List<LOTLSource> lotlList;
	private final Map<CacheKey, ParsingCacheDTO> parsingResults;

	public TLSourceBuilder(List<LOTLSource> lotlList, Map<CacheKey, ParsingCacheDTO> parsingResults) {
		this.lotlList = lotlList;
		this.parsingResults = parsingResults;
	}

	public List<TLSource> build() {
		List<TLSource> result = new ArrayList<TLSource>();
		if (lotlList != null) {
			for (LOTLSource lotlSource : lotlList) {
				ParsingCacheDTO cachedResult = parsingResults.get(lotlSource.getCacheKey());
				List<OtherTSLPointer> tlPointers = cachedResult.getTlOtherPointers();
				for (OtherTSLPointer otherTSLPointerDTO : tlPointers) {
					result.add(getTLSource(otherTSLPointerDTO, lotlSource));
				}
			}
		}
		return result;
	}

	private TLSource getTLSource(OtherTSLPointer otherTSLPointerDTO, LOTLSource lotlSource) {
		TLSource tlSource = new TLSource();
		tlSource.setUrl(otherTSLPointerDTO.getLocation());
		tlSource.setCertificateSource(getCertificateSource(otherTSLPointerDTO.getCertificates()));
		tlSource.setTrustServiceProviderPredicate(lotlSource.getTrustServiceProviderPredicate());
		tlSource.setTrustServicePredicate(lotlSource.getTrustServicePredicate());
		return tlSource;
	}

	private CertificateSource getCertificateSource(List<CertificateToken> certificates) {
		CertificateSource certificateSource = new CommonCertificateSource();
		for (CertificateToken certificate : certificates) {
			certificateSource.addCertificate(certificate);
		}
		return certificateSource;
	}

}
