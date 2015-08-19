package eu.europa.esig.dss.tsl;

import java.util.List;

import eu.europa.esig.dss.x509.CertificateToken;

public class TSLPointer {

	private String url;
	private String territory;
	private String mimeType;
	private List<CertificateToken> potentialSigners;

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

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

	public List<CertificateToken> getPotentialSigners() {
		return potentialSigners;
	}

	public void setPotentialSigners(List<CertificateToken> potentialSigners) {
		this.potentialSigners = potentialSigners;
	}

	@Override
	public String toString() {
		return "TSLPointer [url=" + url + ", territory=" + territory + ", mimeType=" + mimeType + ", potentialSigners=" + potentialSigners + "]";
	}

}
