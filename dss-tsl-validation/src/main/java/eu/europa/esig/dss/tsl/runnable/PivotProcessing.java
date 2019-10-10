package eu.europa.esig.dss.tsl.runnable;

import java.util.List;
import java.util.concurrent.Callable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.tsl.OtherTSLPointer;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.tsl.cache.access.CacheAccessByKey;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.utils.Utils;

public class PivotProcessing extends AbstractAnalysis implements Callable<PivotProcessingResult> {

	private static final Logger LOG = LoggerFactory.getLogger(PivotProcessing.class);

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

			ParsingCacheDTO parsingResult = cacheAccess.getParsingReadOnlyResult();
			if (parsingResult != null) {

				List<OtherTSLPointer> lotlOtherPointers = parsingResult.getLotlOtherPointers();
				int nbLOTLPointersInPivot = Utils.collectionSize(lotlOtherPointers);
				if (nbLOTLPointersInPivot == 1) {
					OtherTSLPointer currentLOTLPointer = lotlOtherPointers.get(0);
					return new PivotProcessingResult(pivot, getLOTLAnnouncedCertificateSource(currentLOTLPointer), currentLOTLPointer.getLocation());
				} else {
					LOG.warn("Unable to find the XML LOTL Pointer in the pivot (nb occurrence : {})", nbLOTLPointersInPivot);
				}
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
