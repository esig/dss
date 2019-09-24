package eu.europa.esig.dss.tsl.job;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.tsl.cache.ParsingCache;
import eu.europa.esig.dss.tsl.cache.state.CachedEntry;
import eu.europa.esig.dss.tsl.dto.OtherTSLPointerDTO;
import eu.europa.esig.dss.tsl.parsing.AbstractParsingResult;
import eu.europa.esig.dss.tsl.parsing.LOTLParsingResult;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;

public class TLSourceBuilder {

	private final List<LOTLSource> lotlList;
	private final ParsingCache parsingCache;

	public TLSourceBuilder(List<LOTLSource> lotlList, ParsingCache parsingCache) {
		this.lotlList = lotlList;
		this.parsingCache = parsingCache;
	}

	public List<TLSource> build() {
		List<TLSource> result = new ArrayList<TLSource>();
		if (lotlList != null) {
			for (LOTLSource lotlSource : lotlList) {
				CachedEntry<AbstractParsingResult> cachedEntry = parsingCache.get(lotlSource.getCacheKey());
				LOTLParsingResult cachedResult = (LOTLParsingResult) cachedEntry.getCachedResult();
				List<OtherTSLPointerDTO> tlPointers = cachedResult.getTlPointers();
				for (OtherTSLPointerDTO otherTSLPointerDTO : tlPointers) {
					result.add(getTLSource(otherTSLPointerDTO, lotlSource));
				}
			}
		}
		return result;
	}

	private TLSource getTLSource(OtherTSLPointerDTO otherTSLPointerDTO, LOTLSource lotlSource) {
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
