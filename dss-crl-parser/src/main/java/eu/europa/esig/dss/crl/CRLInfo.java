package eu.europa.esig.dss.crl;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import eu.europa.esig.dss.crl.handler.CRLInfoEventHandler;

public class CRLInfo implements CRLInfoEventHandler {

	private Integer version;
	private String certificateListSignatureAlgorithmOid;
	private X500Principal issuer;
	private Date thisUpdate;
	private Date nextUpdate;
	private String tbsSignatureAlgorithmOid;
	private byte[] signatureValue;
	private Map<String, byte[]> criticalExtensions = new HashMap<String, byte[]>();
	private Map<String, byte[]> nonCriticalExtensions = new HashMap<String, byte[]>();

	public Integer getVersion() {
		return version;
	}

	@Override
	public void onVersion(int version) {
		this.version = version;
	}

	public String getCertificateListSignatureAlgorithmOid() {
		return certificateListSignatureAlgorithmOid;
	}

	@Override
	public void onCertificateListSignatureAlgorithm(String oid) {
		this.certificateListSignatureAlgorithmOid = oid;
	}

	public X500Principal getIssuer() {
		return issuer;
	}

	@Override
	public void onIssuer(X500Principal issuer) {
		this.issuer = issuer;
	}

	public Date getThisUpdate() {
		return thisUpdate;
	}

	@Override
	public void onThisUpdate(Date thisUpdate) {
		this.thisUpdate = thisUpdate;
	}

	public Date getNextUpdate() {
		return nextUpdate;
	}

	@Override
	public void onNextUpdate(Date nextUpdate) {
		this.nextUpdate = nextUpdate;
	}

	@Override
	public void onCriticalExtension(String oid, byte[] content) {
		this.criticalExtensions.put(oid, content);
	}

	public Map<String, byte[]> getCriticalExtensions() {
		return criticalExtensions;
	}

	public byte[] getCriticalExtension(String oid) {
		return criticalExtensions.get(oid);
	}

	@Override
	public void onNonCriticalExtension(String oid, byte[] content) {
		this.nonCriticalExtensions.put(oid, content);
	}

	public Map<String, byte[]> getNonCriticalExtensions() {
		return nonCriticalExtensions;
	}

	public byte[] getNonCriticalExtension(String oid) {
		return nonCriticalExtensions.get(oid);
	}

	public String getTbsSignatureAlgorithmOid() {
		return tbsSignatureAlgorithmOid;
	}

	@Override
	public void onTbsSignatureAlgorithm(String signatureAlgorithmOid) {
		this.tbsSignatureAlgorithmOid = signatureAlgorithmOid;
	}

	public byte[] getSignatureValue() {
		return signatureValue;
	}

	@Override
	public void onSignatureValue(byte[] signatureValue) {
		this.signatureValue = signatureValue;
	}

}
