package eu.europa.esig.dss.tsl.runnable;

import java.util.List;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.service.http.commons.DSSFileLoader;
import eu.europa.esig.dss.tsl.cache.CacheAccessByKey;
import eu.europa.esig.dss.tsl.parsing.LOTLParsingResult;
import eu.europa.esig.dss.tsl.parsing.LOTLParsingTask;
import eu.europa.esig.dss.tsl.source.LOTLSource;

public class LOTLWithPivotsAnalysis extends AbstractAnalysis implements Runnable {

	private final LOTLSource source;
	private final CacheAccessByKey cacheAccess;

	public LOTLWithPivotsAnalysis(LOTLSource source, CacheAccessByKey cacheAccess, DSSFileLoader dssFileLoader) {
		super(cacheAccess, dssFileLoader);
		this.source = source;
		this.cacheAccess = cacheAccess;
	}

	@Override
	public void run() {

		DSSDocument document = download(source.getUrl());

		if (document != null) {

			LOTLParsingResult lotlParsing = lotlParsing(document);
			if (lotlParsing != null) {

				List<String> pivotURLs = lotlParsing.getPivotURLs();

			}

			validation(document, source.getCertificateSource().getCertificates());
		}

	}

	private LOTLParsingResult lotlParsing(DSSDocument document) {
		// True if EMPTY / EXPIRED by TL/LOTL
		if (cacheAccess.isParsingRefreshNeeded()) {
			try {
				LOTLParsingTask parsingTask = new LOTLParsingTask(source, document);
				LOTLParsingResult parsingResult = parsingTask.get();
				cacheAccess.update(parsingResult);
				return parsingResult;
			} catch (Exception e) {
				cacheAccess.parsingError(e);
			}
		}
		return (LOTLParsingResult) cacheAccess.getParsingResult();
	}

}
