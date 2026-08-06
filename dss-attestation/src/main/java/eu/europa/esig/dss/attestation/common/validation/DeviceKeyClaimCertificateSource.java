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
package eu.europa.esig.dss.attestation.common.validation;

import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimDeviceKey;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.ProofOfPossessionCertificateSource;
import eu.europa.esig.dss.spi.x509.TokenCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.util.List;
import java.util.Objects;

/**
 * Certificate source containing certificates extracted from a "cnf" header (RFC 7800 "3.1. Confirmation Claim")
 *
 */
public class DeviceKeyClaimCertificateSource extends TokenCertificateSource implements ProofOfPossessionCertificateSource {

    private static final long serialVersionUID = 9142049850205709206L;

    private static final Logger LOG = LoggerFactory.getLogger(DeviceKeyClaimCertificateSource.class);

    /** The "cnf" claim value incorporated in SD-JWT */
    private final VerifiedClaimDeviceKey claimDeviceKey;

    /**
     * Default constructor
     *
     * @param claimDeviceKey {@link VerifiedClaimDeviceKey}
     */
    public DeviceKeyClaimCertificateSource(final VerifiedClaimDeviceKey claimDeviceKey) {
        Objects.requireNonNull(claimDeviceKey, "Device key claim cannot be null");
        this.claimDeviceKey = claimDeviceKey;

        extractPublicKey();
        extractCertificates();
        extractDigestReferences();
        extractKidReferences();
        extractUrlReferences();
    }

    private void extractPublicKey() {
        PublicKey publicKey = claimDeviceKey.getPublicKey();
        if (publicKey != null) {
            CertificateRef certificateRef = new CertificateRef();
            certificateRef.setPublicKey(publicKey);
            addCertificateRef(certificateRef, CertificateRefOrigin.PUBLIC_KEY);
        }
    }

    private void extractCertificates() {
        List<CertificateToken> certificates = claimDeviceKey.getCertificates();
        if (Utils.isCollectionNotEmpty(certificates)) {
            if (Utils.collectionSize(certificates) != 1) {
                LOG.warn("More than one certificate found in a 'x5c' certificate chain within a JWK confirmation claim!" );
            }
            for (CertificateToken certificateToken : certificates) {
                addCertificate(certificateToken, CertificateOrigin.ATTESTATION);
            }
        }
    }

    private void extractDigestReferences() {
        List<Digest> certificateDigests = claimDeviceKey.getCertificateDigests();
        if (Utils.isCollectionNotEmpty(certificateDigests)) {
            for (Digest digest : certificateDigests) {
                CertificateRef certRef = new CertificateRef();
                certRef.setCertDigest(digest);
                addCertificateRef(certRef, CertificateRefOrigin.SIGNING_CERTIFICATE);
            }
        }
    }

    private void extractKidReferences() {
        List<String> certificateKeyIdentifiers = claimDeviceKey.getCertificateKeyIdentifiers();
        if (Utils.isCollectionNotEmpty(certificateKeyIdentifiers)) {
            for (String kid : certificateKeyIdentifiers) {
                CertificateRef certRef = new CertificateRef();
                certRef.setKid(kid);
                addCertificateRef(certRef, CertificateRefOrigin.KEY_IDENTIFIER);
            }
        }
    }

    private void extractUrlReferences() {
        List<String> certificateUrls = claimDeviceKey.getCertificateUrls();
        if (Utils.isCollectionNotEmpty(certificateUrls)) {
            for (String url : certificateUrls) {
                CertificateRef certRef = new CertificateRef();
                certRef.setX509Url(url);
                addCertificateRef(certRef, CertificateRefOrigin.X509_URL);
            }
        }
    }

    @Override
    public CertificateSourceType getCertificateSourceType() {
        return CertificateSourceType.ATTESTATION;
    }

}
