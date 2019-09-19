package eu.europa.esig.dss.tsl.callable;

import java.util.concurrent.Callable;

import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.tsl.cache.TLAnalysisCacheAccess;
import eu.europa.esig.dss.tsl.download.XmlDownloadResult;
import eu.europa.esig.dss.tsl.download.XmlDownloadTask;
import eu.europa.esig.dss.tsl.parsing.TLParsingTask;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.tsl.validation.TLValidatorTask;

public class TLAnalysis implements Callable<AnalysisResult> {

	private final TLSource source;
	private final TLAnalysisCacheAccess cacheAccess;
	private final DataLoader dataLoader;

	public TLAnalysis(TLSource source, TLAnalysisCacheAccess cacheAccess, DataLoader dataLoader) {
		this.source = source;
		this.cacheAccess = cacheAccess;
		this.dataLoader = dataLoader;
	}

	@Override
	public AnalysisResult call() throws Exception {

		AnalysisResult result = new AnalysisResult();

		XmlDownloadResult cachedDownloadResult = cacheAccess.getCachedDownloadResult();

		XmlDownloadTask downloadTask = new XmlDownloadTask(dataLoader, source.getUrl());
		XmlDownloadResult newXMLDownloadResult = downloadTask.get();
		if (newXMLDownloadResult != null) {

			if (isChangeDetected(cachedDownloadResult, newXMLDownloadResult)) {
				cacheAccess.expireParsing();
				cacheAccess.expireValidation();
				result.setDownloadResult(newXMLDownloadResult);
			}

			// True if EMPTY / EXPIRED by TL/LOTL
			if (cacheAccess.isParsingRefreshNeeded()) {
				TLParsingTask parsingTask = new TLParsingTask(source, newXMLDownloadResult.getDSSDocument());
				result.setParsingResult(parsingTask.get()); // TODO handle exception
			}

			// True if EMPTY / EXPIRED by TL/LOTL
			if (cacheAccess.isValidationRefreshNeeded()) {
				TLValidatorTask validationTask = new TLValidatorTask(newXMLDownloadResult.getDSSDocument(), source.getCertificateSource().getCertificates());
				result.setValidationResult(validationTask.get()); // TODO handle exception
			}
		}

		return result;
	}

	private boolean isChangeDetected(XmlDownloadResult cachedDownloadResult, XmlDownloadResult newXMLDownloadResult) {
		return !newXMLDownloadResult.getDigest().equals(cachedDownloadResult.getDigest());
	}

}
