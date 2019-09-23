package eu.europa.esig.dss.tsl.runnable;

import java.util.concurrent.CountDownLatch;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.service.http.commons.DSSFileLoader;
import eu.europa.esig.dss.tsl.cache.CacheAccessByKey;
import eu.europa.esig.dss.tsl.download.XmlDownloadResult;
import eu.europa.esig.dss.tsl.download.XmlDownloadTask;
import eu.europa.esig.dss.tsl.parsing.TLParsingTask;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.tsl.validation.TLValidatorTask;

public class TLAnalysis implements Runnable {

	private final TLSource source;
	private final CacheAccessByKey cacheAccess;
	private final DSSFileLoader dssFileLoader;
	private final CountDownLatch latch;

	public TLAnalysis(TLSource source, CacheAccessByKey cacheAccess, DSSFileLoader dssFileLoader, CountDownLatch latch) {
		this.source = source;
		this.cacheAccess = cacheAccess;
		this.dssFileLoader = dssFileLoader;
		this.latch = latch;
	}

	@Override
	public void run() {

		DSSDocument document = download();

		if (document != null) {
			parsing(document);
			validation(document);
		}

		latch.countDown();
	}

	private DSSDocument download() {
		DSSDocument document = null;
		try {
			XmlDownloadTask downloadTask = new XmlDownloadTask(dssFileLoader, source.getUrl());
			XmlDownloadResult downloadResult = downloadTask.get();
			if (!cacheAccess.isUpToDate(downloadResult)) {
				cacheAccess.update(downloadResult);
				cacheAccess.expireParsing();
				cacheAccess.expireValidation();
			}
			document = downloadResult.getDSSDocument();
		} catch (Exception e) {
			cacheAccess.downloadError(e);
		}
		return document;
	}

	private void parsing(DSSDocument document) {
		// True if EMPTY / EXPIRED by TL/LOTL
		if (cacheAccess.isParsingRefreshNeeded()) {
			try {
				TLParsingTask parsingTask = new TLParsingTask(source, document);
				cacheAccess.update(parsingTask.get());
			} catch (Exception e) {
				cacheAccess.parsingError(e);
			}
		}
	}

	private void validation(DSSDocument document) {
		// True if EMPTY / EXPIRED by TL/LOTL
		if (cacheAccess.isValidationRefreshNeeded()) {
			try {
				TLValidatorTask validationTask = new TLValidatorTask(document, source.getCertificateSource().getCertificates());
				cacheAccess.update(validationTask.get());
			} catch (Exception e) {
				cacheAccess.validationError(e);
			}
		}
	}

}
