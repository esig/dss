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
package eu.europa.esig.dss.pki.x509.revocation.ocsp;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.exception.PKIException;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.CertEntityRepository;
import eu.europa.esig.dss.utils.Utils;

import java.util.Map;

/**
 * The PkiOCSPSource class implements the OCSPSource interface for obtaining revocation tokens.
 * It retrieves OCSP responses for a given certificate by sending OCSP requests to a specified OCSP responder.
 *
 */
public class PKIDelegatedOCSPSource extends PKIOCSPSource {

    private static final long serialVersionUID = 1812419786179539363L;

    /** Map of CA cert entities and their delegated OCSP Responders */
    private Map<CertEntity, CertEntity> ocspResponders;

    /**
     * Default constructor
     *
     * @param certEntityRepository {@link CertEntityRepository}
     */
    public PKIDelegatedOCSPSource(final CertEntityRepository certEntityRepository) {
        super(certEntityRepository);
    }

    /**
     * Sets a map of CA cert entities and their delegated OCSP Responders
     *
     * @param ocspResponders a map between CA {@link CertEntity}s and delegated OCSP Responder {@link CertEntity}s
     */
    public void setOcspResponders(Map<CertEntity, CertEntity> ocspResponders) {
        this.ocspResponders = ocspResponders;
    }

    @Override
    public void setOcspResponder(CertEntity ocspResponder) {
        throw new UnsupportedOperationException("Method #setOcspResponder is not supported " +
                "within PKIDelegatedOCSPSource class. Use #setOcspResponders method instead.");
    }

    @Override
    protected CertEntity getOcspResponder(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
        CertEntity issuerCertEntity = certEntityRepository.getByCertificateToken(issuerCertificateToken);
        if (issuerCertEntity == null) {
            throw new PKIException(String.format("CertEntity for certificate token with Id '%s' " +
                            "not found in the repository! Provide a valid issuer.",
                    issuerCertificateToken.getDSSIdAsString()));
        }
        if (Utils.isMapNotEmpty(ocspResponders)) {
            CertEntity ocspResponder = ocspResponders.get(issuerCertEntity);
            if (ocspResponder != null) {
                return ocspResponder;
            }
        }
        return issuerCertEntity;
    }

}
