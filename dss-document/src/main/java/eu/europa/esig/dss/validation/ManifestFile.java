package eu.europa.esig.dss.validation;

import java.util.List;

public class ManifestFile {

	private String filename;
	private String signatureFilename;
	private List<String> entries;

	public String getFilename() {
		return filename;
	}

	public void setFilename(String filename) {
		this.filename = filename;
	}

	public String getSignatureFilename() {
		return signatureFilename;
	}

	public void setSignatureFilename(String signatureFilename) {
		this.signatureFilename = signatureFilename;
	}

	public List<String> getEntries() {
		return entries;
	}

	public void setEntries(List<String> entries) {
		this.entries = entries;
	}

}
