package eu.europa.esig.dss.crl.handler;

import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.Extensions;

import eu.europa.esig.dss.SignatureAlgorithm;

public interface CRLInfoEventHandler {

	void onVersion(int version);

	void onCertificateListSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm);

	void onIssuer(X500Principal issuer);

	void onThisUpdate(Date thisUpdate);

	void onNextUpdate(Date nextUpdate);

	void onCrlExtensions(Extensions extensions);

	void onTbsSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm);

	void onSignatureValue(byte[] signatureValue);

}
