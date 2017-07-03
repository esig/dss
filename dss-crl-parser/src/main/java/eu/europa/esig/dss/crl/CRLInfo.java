package eu.europa.esig.dss.crl;

import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.Extensions;

import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.crl.handler.CRLInfoEventHandler;

public class CRLInfo implements CRLInfoEventHandler {

	private Integer version;
	private SignatureAlgorithm certificateListSignatureAlgorithm;
	private X500Principal issuer;
	private Date thisUpdate;
	private Date nextUpdate;
	private Extensions crlExtensions;
	private SignatureAlgorithm tbsSignatureAlgorithm;
	private byte[] signatureValue;

	public Integer getVersion() {
		return version;
	}

	@Override
	public void onVersion(int version) {
		this.version = version;
	}

	public SignatureAlgorithm getCertificateListSignatureAlgorithm() {
		return certificateListSignatureAlgorithm;
	}

	@Override
	public void onCertificateListSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
		this.certificateListSignatureAlgorithm = signatureAlgorithm;
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

	public Extensions getCrlExtensions() {
		return crlExtensions;
	}

	@Override
	public void onCrlExtensions(Extensions extensions) {
		this.crlExtensions = extensions;
	}

	public SignatureAlgorithm getTbsSignatureAlgorithm() {
		return tbsSignatureAlgorithm;
	}

	@Override
	public void onTbsSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
		this.tbsSignatureAlgorithm = signatureAlgorithm;
	}

	public byte[] getSignatureValue() {
		return signatureValue;
	}

	@Override
	public void onSignatureValue(byte[] signatureValue) {
		this.signatureValue = signatureValue;
	}

}
