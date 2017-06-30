package eu.europa.esig.dss.crl.handler;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface SignatureEventHandler {

	void onSignatureValue(byte[] signatureValue);

	void onSignatureAlgorithm(ASN1ObjectIdentifier oid);

}
