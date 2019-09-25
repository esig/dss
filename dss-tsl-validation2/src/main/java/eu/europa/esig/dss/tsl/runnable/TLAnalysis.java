package eu.europa.esig.dss.tsl.runnable;

import java.util.concurrent.CountDownLatch;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.service.http.commons.DSSFileLoader;
import eu.europa.esig.dss.tsl.cache.CacheAccessByKey;
import eu.europa.esig.dss.tsl.parsing.TLParsingTask;
import eu.europa.esig.dss.tsl.source.TLSource;

public class TLAnalysis extends AbstractAnalysis implements Runnable {

	private static final Logger LOG = LoggerFactory.getLogger(TLAnalysis.class);

	private final TLSource source;
	private final CacheAccessByKey cacheAccess;
	private final CountDownLatch latch;

	public TLAnalysis(TLSource source, CacheAccessByKey cacheAccess, DSSFileLoader dssFileLoader, CountDownLatch latch) {
		super(cacheAccess, dssFileLoader);
		this.source = source;
		this.cacheAccess = cacheAccess;
		this.latch = latch;
	}

	@Override
	public void run() {

		DSSDocument document = download(source.getUrl());

		if (document != null) {
			trustedListParsing(document);

			validation(document, source.getCertificateSource().getCertificates());
		}
		
		latch.countDown();
		
	}

	private void trustedListParsing(DSSDocument document) {
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

}
