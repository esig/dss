package eu.europa.esig.dss.tsl.download;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.tsl.cache.CachedResult;

public class XmlDownloadResult implements CachedResult {

	private final String url; // TODO: needed ?
	private final DSSDocument dssDocument;
	private final Digest digest; // digest of a canonicalized document
	// TODO init from CACHE / ONLINE

	public XmlDownloadResult(String url, DSSDocument dssDocument, Digest digest) {
		this.url = url;
		this.dssDocument = dssDocument;
		this.digest = digest;
	}

	public String getUrl() {
		return url;
	}

	public DSSDocument getDSSDocument() {
		return dssDocument;
	}

	public Digest getDigest() {
		return digest;
	}

}
