package eu.europa.esig.dss.tsl;

import java.util.Date;

public class TSLValidationModel {

	private String url;
	private String filepath;
	private String sha256FileContent;

	private boolean certificateSourceSynchronized;
	private Date loadedDate;

	private TSLParserResult parseResult;
	private TSLValidationResult validationResult;

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getFilepath() {
		return filepath;
	}

	public void setFilepath(String filepath) {
		this.filepath = filepath;
	}

	public String getSha256FileContent() {
		return sha256FileContent;
	}

	public void setSha256FileContent(String sha256FileContent) {
		this.sha256FileContent = sha256FileContent;
	}

	public boolean isCertificateSourceSynchronized() {
		return certificateSourceSynchronized;
	}

	public void setCertificateSourceSynchronized(boolean certificateSourceSynchronized) {
		this.certificateSourceSynchronized = certificateSourceSynchronized;
	}

	public Date getLoadedDate() {
		return loadedDate;
	}

	public void setLoadedDate(Date loadedDate) {
		this.loadedDate = loadedDate;
	}

	public TSLParserResult getParseResult() {
		return parseResult;
	}

	public void setParseResult(TSLParserResult parseResult) {
		this.parseResult = parseResult;
	}

	public TSLValidationResult getValidationResult() {
		return validationResult;
	}

	public void setValidationResult(TSLValidationResult validationResult) {
		this.validationResult = validationResult;
	}

}
