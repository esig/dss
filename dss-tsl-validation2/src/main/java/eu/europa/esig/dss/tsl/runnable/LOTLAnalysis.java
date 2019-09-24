package eu.europa.esig.dss.tsl.runnable;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.service.http.commons.DSSFileLoader;
import eu.europa.esig.dss.tsl.cache.CacheAccessByKey;
import eu.europa.esig.dss.tsl.parsing.LOTLParsingTask;
import eu.europa.esig.dss.tsl.source.LOTLSource;

public class LOTLAnalysis extends AbstractAnalysis implements Runnable {

	private final LOTLSource source;
	private final CacheAccessByKey cacheAccess;

	public LOTLAnalysis(LOTLSource source, CacheAccessByKey cacheAccess, DSSFileLoader dssFileLoader) {
		super(cacheAccess, dssFileLoader);
		this.source = source;
		this.cacheAccess = cacheAccess;
	}

	@Override
	public void run() {

		DSSDocument document = download(source.getUrl());

		if (document != null) {
			loltParsing(document);

			validation(document, source.getCertificateSource().getCertificates());
		}

	}

	private void loltParsing(DSSDocument document) {
		// True if EMPTY / EXPIRED by TL/LOTL
		if (cacheAccess.isParsingRefreshNeeded()) {
			try {
				LOTLParsingTask parsingTask = new LOTLParsingTask(source, document);
				cacheAccess.update(parsingTask.get());
			} catch (Exception e) {
				cacheAccess.parsingError(e);
			}
		}
	}

}
