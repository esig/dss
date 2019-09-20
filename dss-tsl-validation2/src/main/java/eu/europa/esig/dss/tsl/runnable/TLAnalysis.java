package eu.europa.esig.dss.tsl.runnable;

import eu.europa.esig.dss.service.http.commons.DSSFileLoader;
import eu.europa.esig.dss.tsl.cache.TLAnalysisCacheAccess;
import eu.europa.esig.dss.tsl.download.XmlDownloadResult;
import eu.europa.esig.dss.tsl.download.XmlDownloadTask;
import eu.europa.esig.dss.tsl.parsing.TLParsingTask;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.tsl.validation.TLValidatorTask;

public class TLAnalysis implements Runnable {

	private final TLSource source;
	private final TLAnalysisCacheAccess cacheAccess;
	private final DSSFileLoader dssFileLoader;

	public TLAnalysis(TLSource source, TLAnalysisCacheAccess cacheAccess, DSSFileLoader dssFileLoader) {
		this.source = source;
		this.cacheAccess = cacheAccess;
		this.dssFileLoader = dssFileLoader;
	}

	@Override
	public void run() {

		XmlDownloadResult downloadResult = null;
		try {
			XmlDownloadTask downloadTask = new XmlDownloadTask(dssFileLoader, source.getUrl());
			downloadResult = downloadTask.get();
			if (!cacheAccess.isUpToDate(downloadResult)) {
				cacheAccess.expireParsing();
				cacheAccess.expireValidation();
				cacheAccess.update(downloadResult);
			}
		} catch (Exception e) {
			cacheAccess.downloadError(e);
			return;
		}

		// True if EMPTY / EXPIRED by TL/LOTL
		if (cacheAccess.isParsingRefreshNeeded()) {
			try {
				TLParsingTask parsingTask = new TLParsingTask(source, downloadResult.getDSSDocument());
				cacheAccess.update(parsingTask.get());
			} catch (Exception e) {
				cacheAccess.parsingError(e);
			}
		}

		// True if EMPTY / EXPIRED by TL/LOTL
		if (cacheAccess.isValidationRefreshNeeded()) {
			try {
				TLValidatorTask validationTask = new TLValidatorTask(downloadResult.getDSSDocument(), source.getCertificateSource().getCertificates());
				cacheAccess.update(validationTask.get());
			} catch (Exception e) {
				cacheAccess.validationError(e);
			}
		}

	}


}
