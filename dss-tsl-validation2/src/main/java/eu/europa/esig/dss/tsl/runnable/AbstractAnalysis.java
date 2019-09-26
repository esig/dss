package eu.europa.esig.dss.tsl.runnable;

import java.util.List;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.DSSFileLoader;
import eu.europa.esig.dss.tsl.cache.CacheAccessByKey;
import eu.europa.esig.dss.tsl.download.XmlDownloadResult;
import eu.europa.esig.dss.tsl.download.XmlDownloadTask;
import eu.europa.esig.dss.tsl.parsing.LOTLParsingTask;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.validation.TLValidatorTask;

public abstract class AbstractAnalysis {

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
			XmlDownloadTask downloadTask = new XmlDownloadTask(dssFileLoader, url);
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

	protected void lotlParsing(LOTLSource source, DSSDocument document) {
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

	protected void validation(DSSDocument document, List<CertificateToken> trustedCertificates) {
		// True if EMPTY / EXPIRED by TL/LOTL
		if (cacheAccess.isValidationRefreshNeeded()) {
			try {
				TLValidatorTask validationTask = new TLValidatorTask(document, trustedCertificates);
				cacheAccess.update(validationTask.get());
			} catch (Exception e) {
				cacheAccess.validationError(e);
			}
		}
	}

}
