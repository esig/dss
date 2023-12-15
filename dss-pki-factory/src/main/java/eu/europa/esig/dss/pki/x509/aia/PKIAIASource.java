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
package eu.europa.esig.dss.pki.x509.aia;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.exception.PKIException;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.CertEntityRepository;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Implementation of {@code AIASource} used to return a list of CA issuers for the provided {@code CertificateToken},
 * available in the current PKI {@code CertEntityRepository}.
 *
 */
public class PKIAIASource implements AIASource {

    private static final long serialVersionUID = 6081957919058132853L;

    private static final Logger LOG = LoggerFactory.getLogger(PKIAIASource.class);

    /**
     * The repository managing the PKI
     */
    private final CertEntityRepository certEntityRepository;

    /**
     * Defines whether a complete certificate chain should be returned, or only the certificate's issuer certificate
     * Default: TRUE (complete certificate chain is returned)
     */
    private boolean completeCertificateChain = true;

    /**
     * Default constructor to instantiate the {@code PKIAIASource} with the given PKI {@code CertEntityRepository}
     *
     * @param certEntityRepository {@link CertEntityRepository} managing the PKI entities
     */
    public PKIAIASource(CertEntityRepository<? extends CertEntity> certEntityRepository) {
        Objects.requireNonNull(certEntityRepository, "Certificate repository shall be provided!");
        this.certEntityRepository = certEntityRepository;
    }

    /**
     * Sets whether a complete certificate chain should be returned by the current instance.
     * If set to TRUE, returns a complete certificate chain for the given certificate token.
     * If set to FALSE, returns only the certificate token's issuer certificate.
     * Default: TRUE (returns complete certificate chain)
     *
     * @param completeCertificateChain whether a complete certificate chain should be returned
     */
    public void setCompleteCertificateChain(boolean completeCertificateChain) {
        this.completeCertificateChain = completeCertificateChain;
    }

    @Override
    @SuppressWarnings("unchecked")
    public Set<CertificateToken> getCertificatesByAIA(CertificateToken certificateToken) {
        Objects.requireNonNull(certificateToken, "Certificate Token parameter is not provided!");

        if (!canGenerate(certificateToken)) {
            return new HashSet<>();
        }

        CertEntity certEntity = getCertEntity(certificateToken);
        List<CertificateToken> certificateChain = certEntity.getCertificateChain();
        if (Utils.isCollectionNotEmpty(certificateChain)) {
            certificateChain.remove(certificateToken);

            if (completeCertificateChain) {
                return new HashSet<>(certificateChain);
            } else if (Utils.isCollectionNotEmpty(certificateChain)) {
                CertEntity issuerCertEntity = certEntityRepository.getIssuer(certEntity);
                if (issuerCertEntity != null) {
                    return new HashSet<>(Collections.singleton(issuerCertEntity.getCertificateToken()));
                }
            }
        }
        return new HashSet<>();
    }

    /**
     * Returns whether the current implementation is able to produce a CA issuers
     * certificate chain for the given {@code certificateToken}
     *
     * @param certificateToken {@link CertificateToken} to produce a CRL for
     * @return TRUE if the current implementation is able to produce a CA issuers
     *         certificate chain for the given certificate, FALSE otherwise
     */
    protected boolean canGenerate(CertificateToken certificateToken) {
        List<String> caIssuersAccessUrls = CertificateExtensionsUtils.getCAIssuersAccessUrls(certificateToken);
        if (Utils.isCollectionEmpty(caIssuersAccessUrls)) {
            LOG.debug("No AIA.caIssuers location found for {}", certificateToken.getDSSIdAsString());
            return false;
        }
        return true;
    }

    /**
     * Returns a certificate chain for the given {@code certificateToken}
     *
     * @param certificateToken {@link CertificateToken} to get certificate chain for
     * @return a list of {@link CertificateToken}s
     */
    protected List<CertificateToken> getCertificateChain(CertificateToken certificateToken) {
        CertEntity certEntity = getCertEntity(certificateToken);
        List<CertificateToken> certificateChain = new ArrayList<>(certEntity.getCertificateChain());
        certificateChain.remove(certificateToken);
        return certificateChain;
    }

    /**
     * Returns a cert entity for the corresponding {@code eu.europa.esig.dss.model.x509.CertificateToken}
     *
     * @param certificateToken {@link CertificateToken} to get the corresponding cert entity
     * @return {@link CertEntity}
     */
    protected CertEntity getCertEntity(CertificateToken certificateToken) {
        CertEntity certEntity = certEntityRepository.getByCertificateToken(certificateToken);
        if (certEntity == null) {
            throw new PKIException(String.format("CertEntity for certificate token with Id '%s' " +
                    "not found in the repository!", certificateToken.getDSSIdAsString()));
        }
        return certEntity;
    }

}
