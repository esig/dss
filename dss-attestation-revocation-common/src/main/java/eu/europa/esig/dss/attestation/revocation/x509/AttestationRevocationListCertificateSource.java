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
package eu.europa.esig.dss.attestation.revocation.x509;

import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.attestation.claim.ClaimByteString;
import eu.europa.esig.dss.model.attestation.claim.ClaimRevocationList;
import eu.europa.esig.dss.model.attestation.claim.ClaimStatus;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.TokenCertificateSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * Contains certificates extracted from a Token Status List claim present in the EAA payload
 *
 */
public class AttestationRevocationListCertificateSource extends TokenCertificateSource {

    private static final long serialVersionUID = 3937099053754104602L;

    private static final Logger LOG = LoggerFactory.getLogger(AttestationRevocationListCertificateSource.class);

    /** The revocation list claim */
    private final ClaimRevocationList claimRevocationList;

    /**
     * Default constructor
     *
     * @param claimRevocationList {@link ClaimStatus}
     */
    public AttestationRevocationListCertificateSource(final ClaimRevocationList claimRevocationList) {
        Objects.requireNonNull(claimRevocationList, "Claim revocation cannot be null");
        this.claimRevocationList = claimRevocationList;

        extractCertificates();
    }

    private void extractCertificates() {
        ClaimByteString certificateByteString = claimRevocationList.getCertificate();
        if (certificateByteString != null) {
            try {
                CertificateToken certificate = DSSUtils.loadCertificate(certificateByteString.getBinaryValue());
                addCertificate(certificate, CertificateOrigin.EAA);
            } catch (Exception e) {
                LOG.warn("Unable to decode a certificate! Reason : {}", e.getMessage(), e);
            }
        }
    }

    @Override
    public CertificateSourceType getCertificateSourceType() {
        return CertificateSourceType.EAA;
    }

}
