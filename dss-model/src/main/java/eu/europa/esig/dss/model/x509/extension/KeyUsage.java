package eu.europa.esig.dss.model.x509.extension;

import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.KeyUsageBit;

import java.util.List;

/**
 * 4.2.1.3.  Key Usage
 *    The key usage extension defines the purpose (e.g., encipherment,
 *    signature, certificate signing) of the key contained in the
 *    certificate.  The usage restriction might be employed when a key that
 *    could be used for more than one operation is to be restricted.  For
 *    example, when an RSA key should be used only to verify signatures on
 *    objects other than public key certificates and CRLs, the
 *    digitalSignature and/or nonRepudiation bits would be asserted.
 *    Likewise, when an RSA key should be used only for key management, the
 *    keyEncipherment bit would be asserted.
 */
public class KeyUsage extends CertificateExtension {

    private static final long serialVersionUID = 431287385123264310L;

    /** List of defined key usage bits */
    private List<KeyUsageBit> keyUsageBits;

    /**
     * Default constructor
     */
    public KeyUsage() {
        super(CertificateExtensionEnum.KEY_USAGE.getOid());
    }

    /**
     * Returns the key usage bits
     *
     * @return a list of {@link KeyUsageBit}
     */
    public List<KeyUsageBit> getKeyUsageBits() {
        return keyUsageBits;
    }

    /**
     * Sets the key usage bits
     *
     * @param keyUsageBits a list of {@link KeyUsageBit}
     */
    public void setKeyUsageBits(List<KeyUsageBit> keyUsageBits) {
        this.keyUsageBits = keyUsageBits;
    }

}
