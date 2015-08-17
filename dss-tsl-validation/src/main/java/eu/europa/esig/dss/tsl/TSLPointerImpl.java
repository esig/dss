package eu.europa.esig.dss.tsl;

import java.util.List;

import eu.europa.esig.dss.x509.CertificateToken;

public class TSLPointerImpl implements TSLPointer {

	private String xmlUrl;
	private String territory;
	private String mimeType;
	private List<CertificateToken> potentialSigners;

	@Override
	public String getXmlUrl() {
		return xmlUrl;
	}

	public void setXmlUrl(String xmlUrl) {
		this.xmlUrl = xmlUrl;
	}

	@Override
	public String getTerritory() {
		return territory;
	}

	public void setTerritory(String territory) {
		this.territory = territory;
	}

	public String getMimeType() {
		return mimeType;
	}

	public void setMimeType(String mimeType) {
		this.mimeType = mimeType;
	}

	@Override
	public List<CertificateToken> getPotentialSigners() {
		return potentialSigners;
	}

	public void setPotentialSigners(List<CertificateToken> potentialSigners) {
		this.potentialSigners = potentialSigners;
	}

	@Override
	public String toString() {
		return "TSLPointerImpl [xmlUrl=" + xmlUrl + ", territory=" + territory + ", mimeType=" + mimeType + ", potentialSigners=" + potentialSigners + "]";
	}

}
