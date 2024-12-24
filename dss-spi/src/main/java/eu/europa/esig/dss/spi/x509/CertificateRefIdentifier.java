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
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.spi.DSSUtils;

/**
 * An identifier for a certificate token reference
 *
 */
public class CertificateRefIdentifier extends Identifier {

	private static final long serialVersionUID = -957484858420900350L;

	/** The digest algorithm used to compute SKI */
	private static final DigestAlgorithm SKI_DIGEST_ALGO = DigestAlgorithm.SHA1; // by RFC 6960

	/**
	 * Default constructor
	 *
	 * @param certificateRef {@link CertificateRef}
	 */
	protected CertificateRefIdentifier(CertificateRef certificateRef) {
		super("C-", getDigest(certificateRef));
	}

	private static Digest getDigest(CertificateRef certificateRef) {
		Digest certDigest = certificateRef.getCertDigest();
		if (certDigest != null) {
			return certDigest;
		}
		SignerIdentifier signerIdentifier = certificateRef.getCertificateIdentifier();
		if (signerIdentifier != null) {
			if (signerIdentifier.getSki() != null) {
				return new Digest(SKI_DIGEST_ALGO, signerIdentifier.getSki());
			}
			byte[] issuerSerialEncoded = signerIdentifier.getIssuerSerialEncoded();
			if (issuerSerialEncoded != null) {
				return new Digest(DIGEST_ALGO, DSSUtils.digest(DIGEST_ALGO, issuerSerialEncoded));
			}
			if (signerIdentifier.getIssuerName() != null) {
				return new Digest(DIGEST_ALGO, DSSUtils.digest(DIGEST_ALGO, signerIdentifier.getIssuerName().getEncoded()));
			} 
		}
		ResponderId responderId = certificateRef.getResponderId();
		if (responderId != null) {
			if (responderId.getSki() != null) {
				return new Digest(SKI_DIGEST_ALGO, responderId.getSki());
			}
			if (responderId.getX500Principal() != null) {
				return new Digest(DIGEST_ALGO, DSSUtils.digest(DIGEST_ALGO, responderId.getX500Principal().getEncoded()));
			}
		}
		String x509Url = certificateRef.getX509Url();
		if (x509Url != null) {
			return new Digest(DIGEST_ALGO, DSSUtils.digest(DIGEST_ALGO, x509Url.getBytes()));
		}
		throw new DSSException("One of [certDigest, publicKeyDigest, issuerInfo, x509Uri] must be defined for a CertificateRef!");
	}

}
