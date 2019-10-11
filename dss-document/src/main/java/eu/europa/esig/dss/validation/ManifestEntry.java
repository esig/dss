package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.MimeType;

public class ManifestEntry {
	
	private String filename;
	private MimeType mimeType;
	private Digest digest;
	
	// used for reference validation
	private boolean dataFound;
	private boolean dataIntact;
	
	private boolean rootfile;

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
	
	public boolean isFound() {
		return dataFound;
	}
	
	public void setFound(boolean found) {
		this.dataFound = found;
	}
	
	public boolean isIntact() {
		return dataIntact;
	}
	
	public void setIntact(boolean intact) {
		this.dataIntact = intact;
	}
	
	public boolean isRootfile() {
		return rootfile;
	}

	public void setRootfile(boolean rootfile) {
		this.rootfile = rootfile;
	}

}
