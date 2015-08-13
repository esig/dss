package eu.europa.esig.dss.web.model;

import java.util.Date;

public class CertificateDTO {

	private String dssId;
	private String subjetName;
	private String issuerName;
	private Date notBefore;
	private Date notAfter;

	private String sha1Hex;
	private String sha256Hex;
	private String sha1Base64;
	private String sha256Base64;

	public String getDssId() {
		return dssId;
	}

	public void setDssId(String dssId) {
		this.dssId = dssId;
	}

	public String getSubjetName() {
		return subjetName;
	}

	public void setSubjetName(String subjetName) {
		this.subjetName = subjetName;
	}

	public String getIssuerName() {
		return issuerName;
	}

	public void setIssuerName(String issuerName) {
		this.issuerName = issuerName;
	}

	public Date getNotBefore() {
		return notBefore;
	}

	public void setNotBefore(Date notBefore) {
		this.notBefore = notBefore;
	}

	public Date getNotAfter() {
		return notAfter;
	}

	public void setNotAfter(Date notAfter) {
		this.notAfter = notAfter;
	}

	public String getSha1Hex() {
		return sha1Hex;
	}

	public void setSha1Hex(String sha1Hex) {
		this.sha1Hex = sha1Hex;
	}

	public String getSha256Hex() {
		return sha256Hex;
	}

	public void setSha256Hex(String sha256Hex) {
		this.sha256Hex = sha256Hex;
	}

	public String getSha1Base64() {
		return sha1Base64;
	}

	public void setSha1Base64(String sha1Base64) {
		this.sha1Base64 = sha1Base64;
	}

	public String getSha256Base64() {
		return sha256Base64;
	}

	public void setSha256Base64(String sha256Base64) {
		this.sha256Base64 = sha256Base64;
	}

}
