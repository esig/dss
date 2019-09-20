package eu.europa.esig.dss.tsl.download;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.tsl.cache.CachedResult;

public class XmlDownloadResult implements CachedResult {

	private final String url;
	private final byte[] content;
	private final Digest digest;
	// TODO init from CACHE / ONLINE

	public XmlDownloadResult(String url, byte[] content, Digest digest) {
		this.url = url;
		this.content = content;
		this.digest = digest;
	}

	public String getUrl() {
		return url;
	}

	public byte[] getContent() {
		return content;
	}

	public DSSDocument getDSSDocument() {
		return new InMemoryDocument(content);
	}

	public Digest getDigest() {
		return digest;
	}

}
