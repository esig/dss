package eu.europa.esig.dss.signature;

import eu.europa.esig.dss.SignatureValue;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Class used during test to represent the result returned by
 * an external signature process.
 */
public class ExternalSignatureResult {
    private byte[] signedData;
    private SignatureValue signatureValue;
    private X509Certificate signingCertificate;

    public byte[] getSignedData() {
        return signedData;
    }

    public void setSignedData(byte[] signedData) {
        this.signedData = signedData;
    }

    public X509Certificate getSigningCertificate() {
        return signingCertificate;
    }

    public void setSigningCertificate(X509Certificate signingCertificate) { this.signingCertificate = signingCertificate; }

    public SignatureValue getSignatureValue() {
        return signatureValue;
    }

    public void setSignatureValue(SignatureValue signatureValue) {
        this.signatureValue = signatureValue;
    }
}
