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

		XmlDownloadResult downloadResult = null;
		try {
			XmlDownloadTask downloadTask = new XmlDownloadTask(dataLoader, source.getUrl());
			downloadResult = downloadTask.get();
			if (cacheAccess.isUpToDate(downloadResult)) {
				cacheAccess.expireParsing();
				cacheAccess.expireValidation();
				result.setDownloadResult(downloadResult);
			}
		} catch (Exception e) {
			result.setDownloadException(e);
			return result;
		}

		// True if EMPTY / EXPIRED by TL/LOTL
		if (cacheAccess.isParsingRefreshNeeded()) {
			try {
				TLParsingTask parsingTask = new TLParsingTask(source, downloadResult.getDSSDocument());
				result.setParsingResult(parsingTask.get());
			} catch (Exception e) {
				result.setParsingException(e);
			}
		}

		// True if EMPTY / EXPIRED by TL/LOTL
		if (cacheAccess.isValidationRefreshNeeded()) {
			try {
				TLValidatorTask validationTask = new TLValidatorTask(downloadResult.getDSSDocument(), source.getCertificateSource().getCertificates());
				result.setValidationResult(validationTask.get());
			} catch (Exception e) {
				result.setValidationException(e);
			}
		}

		return result;
	}

}
