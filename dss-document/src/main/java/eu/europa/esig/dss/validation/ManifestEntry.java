package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.MimeType;

public class ManifestEntry {
	
	private String filename;
	private MimeType mimeType;
	private Digest digest;
	
	public String getFileName() {
		return filename;
	}
	
	public void setFileName(String fileName) {
		this.filename = fileName;
	}
	
	public MimeType getMimeType() {
		return mimeType;
	}
	
	public void setMimeType(MimeType mimeType) {
		this.mimeType = mimeType;
	}
	
	public Digest getDigest() {
		return digest;
	}
	
	public void setDigest(Digest digest) {
		this.digest = digest;
	}

}
