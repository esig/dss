package eu.europa.esig.dss.crl.handler;

import java.util.Date;

import javax.security.auth.x500.X500Principal;

public interface CRLInfoEventHandler {

	void onVersion(int version);

	void onCertificateListSignatureAlgorithm(String certificateListSignatureAlgorithmOid);

	void onIssuer(X500Principal issuer);

	void onThisUpdate(Date thisUpdate);

	void onNextUpdate(Date nextUpdate);

	void onCriticalExtension(String oid, byte[] content);

	void onNonCriticalExtension(String oid, byte[] content);

	void onTbsSignatureAlgorithm(String tbsSignatureAlgorithmOid);

	void onSignatureValue(byte[] signatureValue);

}
