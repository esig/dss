package eu.europa.esig.dss.tsl.runnable;

import java.util.concurrent.CountDownLatch;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.service.http.commons.DSSFileLoader;
import eu.europa.esig.dss.tsl.cache.CacheAccessByKey;
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
			lotlParsing(source, document);

			validation(document, source.getCertificateSource().getCertificates());
		}

		latch.countDown();
	}

}
