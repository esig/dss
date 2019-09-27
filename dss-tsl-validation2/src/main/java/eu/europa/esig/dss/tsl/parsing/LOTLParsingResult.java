package eu.europa.esig.dss.tsl.parsing;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.spi.tsl.dto.OtherTSLPointer;

public class LOTLParsingResult extends AbstractParsingResult {

	private List<OtherTSLPointer> lotlPointers;
	private List<OtherTSLPointer> tlPointers;

	private String signingCertificateAnnouncementURL;
	private List<String> pivotURLs;
	
	public LOTLParsingResult() {
	}
	
	public LOTLParsingResult(LOTLParsingResult parsingResult) {
		super(parsingResult);
		if (parsingResult.lotlPointers != null) {
			this.lotlPointers = new ArrayList<OtherTSLPointer>(parsingResult.lotlPointers);
		}
		if (parsingResult.tlPointers != null) {
			this.tlPointers = new ArrayList<OtherTSLPointer>(parsingResult.tlPointers);
		}
		this.signingCertificateAnnouncementURL = parsingResult.signingCertificateAnnouncementURL;
		if (parsingResult.pivotURLs != null) {
			this.pivotURLs = new ArrayList<String>(parsingResult.pivotURLs);
		}
	}

	public List<OtherTSLPointer> getLotlPointers() {
		return lotlPointers;
	}

	public void setLotlPointers(List<OtherTSLPointer> lotlPointers) {
		this.lotlPointers = lotlPointers;
	}

	public List<OtherTSLPointer> getTlPointers() {
		return tlPointers;
	}

	public void setTlPointers(List<OtherTSLPointer> tlPointers) {
		this.tlPointers = tlPointers;
	}

	public String getSigningCertificateAnnouncementURL() {
		return signingCertificateAnnouncementURL;
	}

	public void setSigningCertificateAnnouncementURL(String signingCertificateAnnouncementURL) {
		this.signingCertificateAnnouncementURL = signingCertificateAnnouncementURL;
	}

	public List<String> getPivotURLs() {
		return pivotURLs;
	}

	public void setPivotURLs(List<String> pivotURLs) {
		this.pivotURLs = pivotURLs;
	}

}
