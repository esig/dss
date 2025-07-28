/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.service.crl;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.FileRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * CRLSource that provides file-based caching functionality for CRL revocation
 * data
 */
public class FileCacheCRLSource extends FileRevocationSource<CRL> implements CRLSource {

    private static final Logger LOG = LoggerFactory.getLogger(FileCacheCRLSource.class);

    private static final long serialVersionUID = 1L;

    /**
     * @param cacheDirectory {@link File} the directory where cached CRL files will
     *                       be stored
     */
    public FileCacheCRLSource(File cacheDirectory) {
        super(cacheDirectory);
    }

    /**
     * @param cacheDirectory path of directory where cached CRL files will be stored
     */
    public FileCacheCRLSource(String cacheDirectory) {
        super(cacheDirectory);
    }

    @Override
    protected RevocationToken<CRL> reconstructTokenFromEncodedData(byte[] encodedData,
            CertificateToken certificateToken,
            CertificateToken issuerCertToken) {
        try {
            CRLBinary crlBinary = CRLUtils.buildCRLBinary(encodedData);
            CRLValidity crlValidity = CRLUtils.buildCRLValidity(crlBinary, issuerCertToken);

            if (crlValidity.isValid()) {
                CRLToken token = new CRLToken(certificateToken, crlValidity);
                token.setExternalOrigin(RevocationOrigin.CACHED);
                return token;
            } else {
                LOG.warn("Invalid CRL validity for certificate: {}", certificateToken.getDSSIdAsString());
                return null;
            }
        } catch (Exception e) {
            LOG.error("Failed to create CRL token from cached data for certificate '{}': {}",
                    certificateToken.getDSSIdAsString(), e.getMessage());
            return null;
        }
    }

    @Override
    protected String getFileExtension() {
        return ".crl";
    }

    @Override
    protected String getRevocationTokenKey(CertificateToken certificateToken, String urlString) {
        return DSSUtils.getNormalizedString(urlString);
    }

    @Override
    protected List<String> getRevocationAccessUrls(CertificateToken certificateToken) {
        return CertificateExtensionsUtils.getCRLAccessUrls(certificateToken);
    }

    @Override
    protected List<String> initRevocationTokenKeys(CertificateToken certificateToken) {
        final List<String> crlUrls = getRevocationAccessUrls(certificateToken);
        final List<String> keys = new ArrayList<>();
        for (String crlUrl : crlUrls) {
            keys.add(getRevocationTokenKey(certificateToken, crlUrl));
        }
        return keys;
    }

    @Override
    public CRLToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken,
            boolean forceRefresh) {
        return (CRLToken) super.getRevocationToken(certificateToken, issuerCertificateToken, forceRefresh);
    }

    @Override
    public CRLToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
        return this.getRevocationToken(certificateToken, issuerCertificateToken, false);
    }
}
