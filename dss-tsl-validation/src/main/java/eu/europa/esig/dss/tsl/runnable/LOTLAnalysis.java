package eu.europa.esig.dss.tsl.runnable;

import java.util.concurrent.CountDownLatch;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.tsl.cache.access.CacheAccessByKey;
import eu.europa.esig.dss.tsl.source.LOTLSource;

public class LOTLAnalysis extends AbstractAnalysis implements Runnable {

	private final LOTLSource source;
	private final CountDownLatch latch;

	public LOTLAnalysis(LOTLSource source, CacheAccessByKey cacheAccess, DSSFileLoader dssFileLoader, CountDownLatch latch) {
		super(cacheAccess, dssFileLoader);
		this.source = source;
		this.latch = latch;
	}

	@Override
	public void run() {

		DSSDocument document = download(source.getUrl());

		if (document != null) {
			lotlParsing(document, source);

			validation(document, source.getCertificateSource());
		}

		latch.countDown();
	}

}
