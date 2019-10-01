package eu.europa.esig.dss.tsl.runnable;

import java.util.concurrent.Callable;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.DSSFileLoader;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.tsl.cache.access.CacheAccessByKey;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.source.LOTLSource;

public class PivotProcessing extends AbstractAnalysis implements Callable<PivotProcessingResult> {

	private final LOTLSource source;
	private final CacheAccessByKey cacheAccess;

	public PivotProcessing(LOTLSource source, CacheAccessByKey cacheAccess, DSSFileLoader dssFileLoader) {
		super(cacheAccess, dssFileLoader);
		this.source = source;
		this.cacheAccess = cacheAccess;
	}

	@Override
	public PivotProcessingResult call() throws Exception {

		DSSDocument pivot = download(source.getUrl());

		if (pivot != null) {

			lotlParsing(pivot, source);

			return new PivotProcessingResult(pivot, getLOTLAnnouncedCertificateSource());
		}

		return null;
	}

	private CertificateSource getLOTLAnnouncedCertificateSource() {
		CertificateSource certificateSource = new CommonCertificateSource();
		ParsingCacheDTO parsingResult = cacheAccess.getParsingReadOnlyResult();
		if (parsingResult != null) {
			for (CertificateToken certificateToken : parsingResult.getLOTLAnnouncedSigningCertificates()) {
				certificateSource.addCertificate(certificateToken);
			}
		}
		return certificateSource;
	}

}
