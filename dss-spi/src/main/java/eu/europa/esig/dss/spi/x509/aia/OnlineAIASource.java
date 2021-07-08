package eu.europa.esig.dss.spi.x509.aia;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.client.http.DataLoader;

import java.io.Serializable;
import java.util.List;

/**
 * This class is used to download certificates by AIA Urls from online resources
 *
 */
public interface OnlineAIASource extends AIASource, Serializable {

    /**
     * Sets the data loader to be used to download a certificate token by AIA
     *
     * @param dataLoader {@link DataLoader}
     */
    void setDataLoader(DataLoader dataLoader);

    /**
     * The method returns a collection of processed URLs and the corresponding downloaded certificates
     *
     * @param certificateToken {@link CertificateToken} to obtain AIA certificates for
     * @return a list of {@link CertificatesAndAIAUrl}s
     */
    List<CertificatesAndAIAUrl> getCertificatesAndAIAUrls(final CertificateToken certificateToken);

    /**
     * This class represent a returned object by the OnlineAIASource
     *
     */
    class CertificatesAndAIAUrl {

        /**
         * AIA Url used to access the certificates
         */
        private String aiaUrl;

        /**
         * A list of certificates obtained from the AIA request
         */
        private List<CertificateToken> certificates;

        /**
         * Default constructor
         *
         * @param aiaUrl {@link String} AIA Url used to download the certificates
         * @param certificates a list of {@link CertificateToken}s downloaded from the AIA Url
         */
        public CertificatesAndAIAUrl(final String aiaUrl, final List<CertificateToken> certificates) {
            this.aiaUrl = aiaUrl;
            this.certificates = certificates;
        }

        /**
         * Gets AIA Url used to download the certificates
         *
         * @return {@link String} AIA Url
         */
        public String getAiaUrl() {
            return aiaUrl;
        }

        /**
         * List of downloaded certificates
         *
         * @return a list of {@link CertificateToken}s
         */
        public List<CertificateToken> getCertificates() {
            return certificates;
        }

    }

}
