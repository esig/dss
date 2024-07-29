package eu.europa.esig.dss.model.x509.extension;

import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;

import java.util.List;

/**
 * 4.2.1.15. Freshest CRL (a.k.a. Delta CRL Distribution Point)
 * <p>
 * The freshest CRL extension identifies how delta CRL information is
 * obtained. The extension MUST be marked as non-critical by conforming
 * CAs. Further discussion of CRL management is contained in Section 5.
 *
 */
public class FreshestCRL extends CertificateExtension {

    private static final long serialVersionUID = 8414843047407478743L;

    /** List of Freshest CRL distribution points */
    private List<String> crlUrls;

    /**
     * Default constructor
     */
    public FreshestCRL() {
        super(CertificateExtensionEnum.FRESHEST_CRL.getOid());
    }

    /**
     * Returns a list of Freshest CRL distribution point URLs
     *
     * @return a list of {@link String}s
     */
    public List<String> getCrlUrls() {
        return crlUrls;
    }

    /**
     * Sets a list of Freshest CRL distribution point URLs
     *
     * @param crlUrls a list of {@link String}s
     */
    public void setCrlUrls(List<String> crlUrls) {
        this.crlUrls = crlUrls;
    }

}
