package eu.europa.esig.dss.crl.handler;

import java.util.Date;

import javax.security.auth.x500.X500Principal;

import eu.europa.esig.dss.SignatureAlgorithm;

public interface CRLInfoEventHandler {

	void onVersion(int version);

	void onCertificateListSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm);

	void onIssuer(X500Principal issuer);

	void onThisUpdate(Date thisUpdate);

	void onNextUpdate(Date nextUpdate);

	void onCriticalExtension(String oid, byte[] content);

	void onNonCriticalExtension(String oid, byte[] content);

	void onTbsSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm);

	void onSignatureValue(byte[] signatureValue);

}
