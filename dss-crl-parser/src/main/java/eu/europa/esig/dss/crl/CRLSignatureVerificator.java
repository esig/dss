package eu.europa.esig.dss.crl;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import eu.europa.esig.dss.crl.handler.SignatureEventHandler;

public class CRLSignatureVerificator implements SignatureEventHandler {

	private byte[] signatureValue;
	private ASN1ObjectIdentifier signatureAlgorithmOid;

	@Override
	public void onSignatureValue(byte[] signatureValue) {
		this.signatureValue = signatureValue;
	}

	@Override
	public void onSignatureAlgorithm(ASN1ObjectIdentifier signatureAlgorithmOid) {
		this.signatureAlgorithmOid = signatureAlgorithmOid;
	}

	public byte[] getSignatureValue() {
		return signatureValue;
	}

	public ASN1ObjectIdentifier getSignatureAlgorithmOid() {
		return signatureAlgorithmOid;
	}

}
