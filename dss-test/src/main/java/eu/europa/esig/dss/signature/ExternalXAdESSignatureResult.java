package eu.europa.esig.dss.signature;

import java.util.Date;

/**
 * Class used during test to represent the result returned by
 * an external XAdES signature process.
 */
public class ExternalXAdESSignatureResult extends ExternalSignatureResult {
    private Date signingDate;
    private byte[] signedAdESObject;

    public Date getSigningDate() { return signingDate; }

    public void setSigningDate(Date signingDate) { this.signingDate = signingDate; }

    public byte[] getSignedAdESObject() {
        return signedAdESObject;
    }

    public void setSignedAdESObject(byte[] signedAdESObject) {
        this.signedAdESObject = signedAdESObject;
    }
}
