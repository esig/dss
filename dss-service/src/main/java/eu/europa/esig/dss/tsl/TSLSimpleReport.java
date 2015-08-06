package eu.europa.esig.dss.tsl;

import java.util.Date;
import java.util.Set;

import eu.europa.esig.dss.x509.CertificateToken;

public class TSLSimpleReport {

	private String url;

	private String country;

	private boolean loaded;

	private boolean allCertificatesLoaded;

	private Date loadedDate;

	private Set<CertificateToken> certificates;

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public boolean isLoaded() {
		return loaded;
	}

	public void setLoaded(boolean loaded) {
		this.loaded = loaded;
	}

	public boolean isAllCertificatesLoaded() {
		return allCertificatesLoaded;
	}

	public void setAllCertificatesLoaded(boolean allCertificatesLoaded) {
		this.allCertificatesLoaded = allCertificatesLoaded;
	}

	public String getCountry() {
		return country;
	}

	public void setCountry(String country) {
		this.country = country;
	}

	public Date getLoadedDate() {
		return loadedDate;
	}

	public void setLoadedDate(Date loadedDate) {
		this.loadedDate = loadedDate;
	}

	public Set<CertificateToken> getCertificates() {
		return certificates;
	}

	public void setCertificates(Set<CertificateToken> certificates) {
		this.certificates = certificates;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((url == null) ? 0 : url.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		TSLSimpleReport other = (TSLSimpleReport) obj;
		if (url == null) {
			if (other.url != null) {
				return false;
			}
		} else if (!url.equals(other.url)) {
			return false;
		}
		return true;
	}

}
