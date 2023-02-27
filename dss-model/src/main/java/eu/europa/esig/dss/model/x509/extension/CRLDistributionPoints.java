package eu.europa.esig.dss.model.x509.extension;

import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;

import java.util.List;

/**
 *
 * 4.2.1.13.  CRL Distribution Points
 * The CRL distribution points extension identifies how CRL information
 * is obtained. The extension SHOULD be non-critical, but this profile
 * RECOMMENDS support for this extension by CAs and applications.
 */
public class CRLDistributionPoints extends CertificateExtension {

    /** List of CRL distribution points */
    private List<String> crlUrls;

    /**
     * Default constructor
     */
    public CRLDistributionPoints() {
        super(CertificateExtensionEnum.CRL_DISTRIBUTION_POINTS.getOid());
    }

    /**
     * Returns a list of CRL distribution point URLs
     *
     * @return a list of {@link String}s
     */
    public List<String> getCrlUrls() {
        return crlUrls;
    }

    /**
     * Sets a list of CRL distribution point URLs
     *
     * @param crlUrls a list of {@link String}s
     */
    public void setCrlUrls(List<String> crlUrls) {
        this.crlUrls = crlUrls;
    }

}
