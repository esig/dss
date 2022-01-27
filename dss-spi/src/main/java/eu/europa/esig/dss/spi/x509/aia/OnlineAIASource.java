/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.x509.aia;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.client.http.DataLoader;

import java.util.List;

/**
 * This class is used to download certificates by AIA Urls from online resources
 *
 */
public interface OnlineAIASource extends AIASource {

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
