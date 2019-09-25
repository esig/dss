package eu.europa.esig.dss.tsl.runnable;

import java.util.concurrent.CountDownLatch;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.service.http.commons.DSSFileLoader;
import eu.europa.esig.dss.tsl.cache.CacheAccessByKey;
import eu.europa.esig.dss.tsl.download.XmlDownloadResult;
import eu.europa.esig.dss.tsl.download.XmlDownloadTask;
import eu.europa.esig.dss.tsl.parsing.TLParsingTask;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.tsl.validation.TLValidatorTask;

public class TLAnalysis implements Runnable {

	private static final Logger LOG = LoggerFactory.getLogger(TLAnalysis.class);

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
			LOG.info("Downloading a remote content from url [{}]...", source.getUrl());
			XmlDownloadTask downloadTask = new XmlDownloadTask(dssFileLoader, source.getUrl());
			XmlDownloadResult downloadResult = downloadTask.get();
			if (!cacheAccess.isUpToDate(downloadResult)) {
				LOG.info("A newer version of file is downloaded from url [{}]. Update operation is in progress...", source.getUrl());
				cacheAccess.update(downloadResult);
				cacheAccess.expireParsing();
				cacheAccess.expireValidation();
			}
			document = downloadResult.getDSSDocument();
			LOG.info("The file from url [{}] was received successfully", source.getUrl());
		} catch (Exception e) {
			LOG.error("An error occurred on an attempt to download a content from url [{}]. Reason : {}", source.getUrl(), e.getMessage());
			cacheAccess.downloadError(e);
		}
		return document;
	}

	private void parsing(DSSDocument document) {
		// True if EMPTY / EXPIRED by TL/LOTL
		if (cacheAccess.isParsingRefreshNeeded()) {
			try {
				LOG.info("Parsing a file received from url [{}]...", source.getUrl());
				TLParsingTask parsingTask = new TLParsingTask(source, document);
				cacheAccess.update(parsingTask.get());
			} catch (Exception e) {
				LOG.error("An error occurred on parsing a file from url [{}]. Reason : {}", source.getUrl(), e.getMessage());
				cacheAccess.parsingError(e);
			}
		}
	}

	private void validation(DSSDocument document) {
		// True if EMPTY / EXPIRED by TL/LOTL
		if (cacheAccess.isValidationRefreshNeeded()) {
			try {
				LOG.info("Validation of a file received from url [{}]...", source.getUrl());
				TLValidatorTask validationTask = new TLValidatorTask(document, source.getCertificateSource().getCertificates());
				cacheAccess.update(validationTask.get());
			} catch (Exception e) {
				LOG.error("An error occurred on validation a file from url [{}]. Reason : {}", source.getUrl(), e.getMessage());
				cacheAccess.validationError(e);
			}
		}
	}

}
