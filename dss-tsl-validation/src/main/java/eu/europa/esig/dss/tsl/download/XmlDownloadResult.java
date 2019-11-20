package eu.europa.esig.dss.tsl.download;

import java.util.Date;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.tsl.cache.CachedResult;

public class XmlDownloadResult implements CachedResult {

	private final DSSDocument dssDocument;
	private final Digest digest; // digest of a canonicalized document
	
	/* The date when the cached file the last time was checked against a file from remote source 
	   Which also represents the last time a successful download was performed */
	private Date lastSuccessDownloadTime;

	public XmlDownloadResult(DSSDocument dssDocument, Digest digest) {
		this.dssDocument = dssDocument;
		this.digest = digest;
		this.lastSuccessDownloadTime = new Date();
	}
	
	public DSSDocument getDSSDocument() {
		return dssDocument;
	}

	public Digest getDigest() {
		return digest;
	}
	
	public Date getLastSuccessDownloadTime() {
		return lastSuccessDownloadTime;
	}
	
	public void setLastSuccessDownloadTime(Date lastSuccessDownloadTime) {
		this.lastSuccessDownloadTime = lastSuccessDownloadTime;
	}

}
