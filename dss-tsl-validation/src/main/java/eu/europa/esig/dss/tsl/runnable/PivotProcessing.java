package eu.europa.esig.dss.tsl.runnable;

import java.util.concurrent.Callable;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.tsl.OtherTSLPointer;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.tsl.cache.access.CacheAccessByKey;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.parsing.ParsingUtils;
import eu.europa.esig.dss.tsl.source.LOTLSource;

public class PivotProcessing extends AbstractAnalysis implements Callable<PivotProcessingResult> {

	private final LOTLSource pivotSource;
	private final CacheAccessByKey cacheAccess;

	public PivotProcessing(LOTLSource source, CacheAccessByKey cacheAccess, DSSFileLoader dssFileLoader) {
		super(cacheAccess, dssFileLoader);
		this.pivotSource = source;
		this.cacheAccess = cacheAccess;
	}

	@Override
	public PivotProcessingResult call() throws Exception {

		DSSDocument pivot = download(pivotSource.getUrl());

		if (pivot != null) {

			lotlParsing(pivot, pivotSource);

			ParsingCacheDTO parsingResult = cacheAccess.getParsingReadOnlyResult();
			OtherTSLPointer xmllotlPointer = ParsingUtils.getXMLLOTLPointer(parsingResult);
			
			if (xmllotlPointer != null) {
				return new PivotProcessingResult(pivot, getLOTLAnnouncedCertificateSource(xmllotlPointer), xmllotlPointer.getLocation());
			}
		}

		return null;
	}

	private CertificateSource getLOTLAnnouncedCertificateSource(OtherTSLPointer currentLOTLPointer) {
		CertificateSource certificateSource = new CommonCertificateSource();
		for (CertificateToken certificate : currentLOTLPointer.getCertificates()) {
			certificateSource.addCertificate(certificate);
		}
		return certificateSource;
	}

}
