package eu.europa.esig.dss.tsl.runnable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.tsl.cache.access.CacheAccessByKey;
import eu.europa.esig.dss.tsl.download.XmlDownloadResult;
import eu.europa.esig.dss.tsl.download.XmlDownloadTask;
import eu.europa.esig.dss.tsl.parsing.LOTLParsingTask;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.validation.TLValidatorTask;

public abstract class AbstractAnalysis {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractAnalysis.class);

	private final CacheAccessByKey cacheAccess;
	private final DSSFileLoader dssFileLoader;

	protected AbstractAnalysis(final CacheAccessByKey cacheAccess, final DSSFileLoader dssFileLoader) {
		this.cacheAccess = cacheAccess;
		this.dssFileLoader = dssFileLoader;
	}

	protected final CacheAccessByKey getCacheAccessByKey() {
		return cacheAccess;
	}

	protected DSSDocument download(final String url) {
		DSSDocument document = null;
		try {
			LOG.debug("Downloading url '{}'...", url);
			XmlDownloadTask downloadTask = new XmlDownloadTask(dssFileLoader, url);
			XmlDownloadResult downloadResult = downloadTask.get();
			if (!cacheAccess.isUpToDate(downloadResult)) {
				cacheAccess.update(downloadResult);
				cacheAccess.expireParsing();
				cacheAccess.expireValidation();
			}
			document = downloadResult.getDSSDocument();
		} catch (Exception e) {
			// wrapped exception
			LOG.error(e.getMessage());
			cacheAccess.downloadError(e);
		}
		return document;
	}

	protected void lotlParsing(DSSDocument document, LOTLSource source) {
		// True if EMPTY / EXPIRED by TL/LOTL
		if (cacheAccess.isParsingRefreshNeeded()) {
			try {
				LOG.debug("Parsing LOTL with cache key '{}'...", source.getCacheKey().getKey());
				LOTLParsingTask parsingTask = new LOTLParsingTask(document, source);
				cacheAccess.update(parsingTask.get());
			} catch (Exception e) {
				LOG.error("Cannot parse the LOTL with the cache key '{}' : {}", source.getCacheKey().getKey(), e.getMessage());
				cacheAccess.parsingError(e);
			}
		}
	}

	protected void validation(DSSDocument document, CertificateSource certificateSource) {
		// True if EMPTY / EXPIRED by TL/LOTL
		if (cacheAccess.isValidationRefreshNeeded()) {
			try {
				LOG.debug("Validating the TL/LOTL with cache key '{}'...", cacheAccess.getCacheKey().getKey());
				TLValidatorTask validationTask = new TLValidatorTask(document, certificateSource);
				cacheAccess.update(validationTask.get());
			} catch (Exception e) {
				LOG.error("Cannot validate the TL/LOTL with the cache key '{}' : {}", cacheAccess.getCacheKey().getKey(), e.getMessage());
				cacheAccess.validationError(e);
			}
		}
	}

}
