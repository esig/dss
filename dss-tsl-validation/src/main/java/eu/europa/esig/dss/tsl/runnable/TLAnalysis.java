package eu.europa.esig.dss.tsl.runnable;

import java.util.concurrent.CountDownLatch;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.tsl.cache.access.CacheAccessByKey;
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

			validation(document, source.getCertificateSource());
		}

		latch.countDown();

	}

	private void trustedListParsing(DSSDocument document) {
		// True if EMPTY / EXPIRED by TL/LOTL
		if (cacheAccess.isParsingRefreshNeeded()) {
			try {
				LOG.debug("Parsing TL with cache key '{}'...", source.getCacheKey().getKey());
				TLParsingTask parsingTask = new TLParsingTask(document, source);
				cacheAccess.update(parsingTask.get());
			} catch (Exception e) {
				LOG.error("Cannot parse the TL with the cache key '{}' : {}", source.getCacheKey().getKey(), e.getMessage());
				cacheAccess.parsingError(e);
			}
		}
	}

}
