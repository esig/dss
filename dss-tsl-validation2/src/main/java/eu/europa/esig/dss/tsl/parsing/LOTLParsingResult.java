package eu.europa.esig.dss.tsl.parsing;

import java.util.List;

import eu.europa.esig.dss.tsl.dto.OtherTSLPointerDTO;

public class LOTLParsingResult extends CommonParsingResult {

	private List<OtherTSLPointerDTO> lotlPointers;
	private List<OtherTSLPointerDTO> tlPointers;

	private String signingCertificateAnnouncementURL;
	private List<String> pivotURLs;

	public List<OtherTSLPointerDTO> getLotlPointers() {
		return lotlPointers;
	}

	public void setLotlPointers(List<OtherTSLPointerDTO> lotlPointers) {
		this.lotlPointers = lotlPointers;
	}

	public List<OtherTSLPointerDTO> getTlPointers() {
		return tlPointers;
	}

	public void setTlPointers(List<OtherTSLPointerDTO> tlPointers) {
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
