package eu.europa.esig.dss.tsl.callable;

import eu.europa.esig.dss.tsl.download.XmlDownloadResult;
import eu.europa.esig.dss.tsl.parsing.AbstractParsingResult;
import eu.europa.esig.dss.tsl.validation.TLValidationResult;

public class AnalysisResult {

	private XmlDownloadResult downloadResult;

	private AbstractParsingResult parsingResult;

	private TLValidationResult validationResult;

	public XmlDownloadResult getDownloadResult() {
		return downloadResult;
	}

	public void setDownloadResult(XmlDownloadResult downloadResult) {
		this.downloadResult = downloadResult;
	}

	public AbstractParsingResult getParsingResult() {
		return parsingResult;
	}

	public void setParsingResult(AbstractParsingResult parsingResult) {
		this.parsingResult = parsingResult;
	}

	public TLValidationResult getValidationResult() {
		return validationResult;
	}

	public void setValidationResult(TLValidationResult validationResult) {
		this.validationResult = validationResult;
	}

}
