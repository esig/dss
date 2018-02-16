package eu.europa.esig.dss.signature;

import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * Class used during test to represent the result returned by
 * an external signature process.
 */
public class ExternalSignatureResult {

	private byte[] signedData;
	private SignatureValue signatureValue;
	private CertificateToken signingCertificate;

	public byte[] getSignedData() {
		return signedData;
	}

	public void setSignedData(byte[] signedData) {
		this.signedData = signedData;
	}

	public CertificateToken getSigningCertificate() {
		return signingCertificate;
	}

	public void setSigningCertificate(CertificateToken signingCertificate) {
		this.signingCertificate = signingCertificate;
	}

	public SignatureValue getSignatureValue() {
		return signatureValue;
	}

	public void setSignatureValue(SignatureValue signatureValue) {
		this.signatureValue = signatureValue;
	}

}
