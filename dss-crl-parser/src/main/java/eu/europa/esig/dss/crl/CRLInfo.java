package eu.europa.esig.dss.crl;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

public class CRLInfo {

	private Integer version;
	private String certificateListSignatureAlgorithmOid;
	private X500Principal issuer;
	private Date thisUpdate;
	private Date nextUpdate;
	private Date expiredCertsOnCRL;
	private String tbsSignatureAlgorithmOid;
	private byte[] signatureValue;
	private Map<String, byte[]> criticalExtensions = new HashMap<String, byte[]>();
	private Map<String, byte[]> nonCriticalExtensions = new HashMap<String, byte[]>();
	private boolean unknownCriticalExtension;
	private String url;

	public Integer getVersion() {
		return version;
	}

	void setVersion(Integer version) {
		this.version = version;
	}

	public String getCertificateListSignatureAlgorithmOid() {
		return certificateListSignatureAlgorithmOid;
	}

	void setCertificateListSignatureAlgorithmOid(String certificateListSignatureAlgorithmOid) {
		this.certificateListSignatureAlgorithmOid = certificateListSignatureAlgorithmOid;
	}

	public X500Principal getIssuer() {
		return issuer;
	}

	void setIssuer(X500Principal issuer) {
		this.issuer = issuer;
	}

	public Date getThisUpdate() {
		return thisUpdate;
	}

	void setThisUpdate(Date thisUpdate) {
		this.thisUpdate = thisUpdate;
	}

	public Date getNextUpdate() {
		return nextUpdate;
	}

	void setNextUpdate(Date nextUpdate) {
		this.nextUpdate = nextUpdate;
	}

	public Date getExpiredCertsOnCRL() {
		return expiredCertsOnCRL;
	}

	void setExpiredCertsOnCRL(Date expiredCertsOnCRL) {
		this.expiredCertsOnCRL = expiredCertsOnCRL;
	}

	public String getTbsSignatureAlgorithmOid() {
		return tbsSignatureAlgorithmOid;
	}

	void setTbsSignatureAlgorithmOid(String tbsSignatureAlgorithmOid) {
		this.tbsSignatureAlgorithmOid = tbsSignatureAlgorithmOid;
	}

	public byte[] getSignatureValue() {
		return signatureValue;
	}

	void setSignatureValue(byte[] signatureValue) {
		this.signatureValue = signatureValue;
	}

	void addCriticalExtension(String oid, byte[] content) {
		this.criticalExtensions.put(oid, content);
	}

	public byte[] getCriticalExtension(String oid) {
		return criticalExtensions.get(oid);
	}

	public Map<String, byte[]> getCriticalExtensions() {
		return criticalExtensions;
	}

	void addNonCriticalExtension(String oid, byte[] content) {
		this.nonCriticalExtensions.put(oid, content);
	}

	public byte[] getNonCriticalExtension(String oid) {
		return nonCriticalExtensions.get(oid);
	}

	public Map<String, byte[]> getNonCriticalExtensions() {
		return nonCriticalExtensions;
	}

	public boolean isUnknownCriticalExtension() {
		return unknownCriticalExtension;
	}

	void setUnknownCriticalExtension(boolean unknownCriticalExtension) {
		this.unknownCriticalExtension = unknownCriticalExtension;
	}

	public String getUrl() {
		return url;
	}

	void setUrl(String url) {
		this.url = url;
	}

}
