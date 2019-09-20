package eu.europa.esig.dss.tsl.callable;

import eu.europa.esig.dss.tsl.download.XmlDownloadResult;
import eu.europa.esig.dss.tsl.parsing.AbstractParsingResult;
import eu.europa.esig.dss.tsl.validation.ValidationResult;

public class AnalysisResult {

	private XmlDownloadResult downloadResult;
	private Exception downloadException;

	private AbstractParsingResult parsingResult;
	private Exception parsingException;

	private ValidationResult validationResult;
	private Exception validationException;

	public XmlDownloadResult getDownloadResult() {
		return downloadResult;
	}

	public void setDownloadResult(XmlDownloadResult downloadResult) {
		this.downloadResult = downloadResult;
	}

	public Exception getDownloadException() {
		return downloadException;
	}

	public void setDownloadException(Exception downloadException) {
		this.downloadException = downloadException;
	}

	public AbstractParsingResult getParsingResult() {
		return parsingResult;
	}

	public void setParsingResult(AbstractParsingResult parsingResult) {
		this.parsingResult = parsingResult;
	}

	public Exception getParsingException() {
		return parsingException;
	}

	public void setParsingException(Exception parsingException) {
		this.parsingException = parsingException;
	}

	public ValidationResult getValidationResult() {
		return validationResult;
	}

	public void setValidationResult(ValidationResult validationResult) {
		this.validationResult = validationResult;
	}

	public Exception getValidationException() {
		return validationException;
	}

	public void setValidationException(Exception validationException) {
		this.validationException = validationException;
	}

}
