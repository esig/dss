package eu.europa.esig.dss.tsl;

import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

public class OtherTrustedList {

	private String countryCode;
	private String url;
	private KeyStoreCertificateSource trustStore;

	public String getCountryCode() {
		return countryCode;
	}

	public void setCountryCode(String countryCode) {
		this.countryCode = countryCode;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public KeyStoreCertificateSource getTrustStore() {
		return trustStore;
	}

	public void setTrustStore(KeyStoreCertificateSource trustStore) {
		this.trustStore = trustStore;
	}

}
