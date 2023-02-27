package eu.europa.esig.dss.model.x509.extension;

import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;

import java.util.List;

/**
 * 4.2.1.12.  Extended Key Usage
 *    This extension indicates one or more purposes for which the certified
 *    public key may be used, in addition to or in place of the basic
 *    purposes indicated in the key usage extension. In general, this
 *    extension will appear only in end entity certificates.
 */
public class ExtendedKeyUsages extends CertificateExtension {

    /** List of extended key usage OIDs */
    private List<String> oids;

    /**
     * Default constructor
     */
    public ExtendedKeyUsages() {
        super(CertificateExtensionEnum.EXTENDED_KEY_USAGE.getOid());
    }

    /**
     * Returns the extended key usage OIDs
     *
     * @return a list of {@link String}s
     */
    public List<String> getOids() {
        return oids;
    }

    /**
     * Sets the extended key usage OIDs
     *
     * @param oids a list of {@link String}s
     */
    public void setOids(List<String> oids) {
        this.oids = oids;
    }

}
