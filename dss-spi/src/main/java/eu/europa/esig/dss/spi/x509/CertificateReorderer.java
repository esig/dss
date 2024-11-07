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

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Reorders a certificate collection to the corresponding certificate chain
 */
public class CertificateReorderer {

	private static final Logger LOG = LoggerFactory.getLogger(CertificateReorderer.class);

	/** The signing certificate (the last certificate in the chain) */
	private final CertificateToken signingCertificate;

	/** The collection of certificates */
	private final Collection<CertificateToken> certificateChain;

	/**
	 * Constructor which takes a collection of certificates where DSS needs to find
	 * the signing certificate
	 * 
	 * @param certificateChain
	 *                         a collection of {@link CertificateToken}s
	 */
	public CertificateReorderer(Collection<CertificateToken> certificateChain) {
		this(null, certificateChain);
	}

	/**
	 * Constructor which takes a potential signing certificate and a certificate chain
	 * 
	 * @param signingCertificate
	 *            {@link CertificateToken} the potential signing certificate
	 * @param certificateChain
	 *            a collection of {@link CertificateToken}s
	 */
	public CertificateReorderer(CertificateToken signingCertificate, Collection<CertificateToken> certificateChain) {
		this.signingCertificate = signingCertificate;
		this.certificateChain = certificateChain;
	}

	/**
	 * This method is used to order the certificates (signing certificate, CA1, CA2 and Root)
	 * 
	 * @return a list of ordered {@link CertificateToken}s
	 */
	public List<CertificateToken> getOrderedCertificates() {

		List<CertificateToken> certificates = getAllCertificatesOnce();
		if (Utils.collectionSize(certificates) == 1) {
			return certificates;
		}

		initIssuerPublicKeys(certificates);

		// Build complete chain
		List<CertificateToken> identifiedSigningCerts = getSigningCertificates(certificates);
		CertificateToken selectedSigningCert = selectSigningCertificateInList(identifiedSigningCerts);

		List<CertificateToken> rebuiltCertificateChain = buildCertificateChainForCert(certificates, selectedSigningCert);

		if (certificates.size() > rebuiltCertificateChain.size()) {
			LOG.debug("Some certificates are ignored");
			LOG.debug("Before : {}", certificates);
			LOG.debug("After : {}", rebuiltCertificateChain);
		}

		return rebuiltCertificateChain;
	}

	/**
	 * This method is used to order the certificates (signing certificate, CA1, CA2
	 * and Root)
	 * 
	 * @return a map of one or more ordered certificates chain
	 */
	public Map<CertificateToken, List<CertificateToken>> getOrderedCertificateChains() {
		Map<CertificateToken, List<CertificateToken>> result = new HashMap<>();
		
		List<CertificateToken> certificates = getAllCertificatesOnce();
		if (Utils.collectionSize(certificates) == 1) {
			CertificateToken uniqueCert = certificates.get(0);
			result.put(uniqueCert, Collections.singletonList(uniqueCert));
			return result;
		}

		initIssuerPublicKeys(certificates);

		List<CertificateToken> identifiedSigningCerts = getSigningCertificates(certificates);
		for (CertificateToken identifiedSigningCert : identifiedSigningCerts) {
			result.put(identifiedSigningCert, buildCertificateChainForCert(certificates, identifiedSigningCert));
		}

		return result;
	}

	private void initIssuerPublicKeys(List<CertificateToken> certificates) {
		// Build the chain cert -> issuer
		for (CertificateToken token : certificates) {
			if (isIssuerNeeded(token)) {
				for (CertificateToken signer : certificates) {
					if (token.isSignedBy(signer)) {
						LOG.debug("{} is signed by {}", token.getDSSIdAsString(), signer.getDSSIdAsString());
						break;
					}
				}
				if (isIssuerNeeded(token)) {
					LOG.warn("Issuer not found for certificate {}", token.getDSSIdAsString());
				}
			}
		}
	}

	private List<CertificateToken> buildCertificateChainForCert(List<CertificateToken> certificates, CertificateToken certToAdd) {
		List<CertificateToken> result = new LinkedList<>();
		while (certToAdd != null && !result.contains(certToAdd)) {
			result.add(certToAdd);
			certToAdd = getCertificateByPubKey(certificates, certToAdd.getPublicKeyOfTheSigner());
		}
		return result;
	}

	private CertificateToken getCertificateByPubKey(List<CertificateToken> certificates, PublicKey publicKeyOfTheSigner) {
		for (CertificateToken certificateToken : certificates) {
			if (certificateToken.getPublicKey().equals(publicKeyOfTheSigner)) {
				return certificateToken;
			}
		}
		return null;
	}

	private boolean isIssuerNeeded(CertificateToken token) {
		return !token.isSelfSigned() && token.getPublicKeyOfTheSigner() == null;
	}

	private CertificateToken selectSigningCertificateInList(List<CertificateToken> identifiedSigningCerts) {
		CertificateToken selectedSigningCert;
		if (identifiedSigningCerts.size() == 1) {
			selectedSigningCert = identifiedSigningCerts.get(0);
		} else {
			LOG.warn("More than one chain detected");
			if (signingCertificate != null && identifiedSigningCerts.contains(signingCertificate)) {
				selectedSigningCert = signingCertificate;
			} else {
				throw new DSSException("Unable to determine a signing certificate : No pertinent input parameters");
			}
		}
		return selectedSigningCert;
	}

	/**
	 * This method is used to avoid duplicate entries
	 * 
	 * @return a list with all certificates
	 */
	private List<CertificateToken> getAllCertificatesOnce() {
		List<CertificateToken> result = new ArrayList<>();

		if (signingCertificate != null) {
			result.add(signingCertificate);
		}

		if (Utils.isCollectionNotEmpty(certificateChain)) {
			for (CertificateToken certificateToken : certificateChain) {
				if (certificateToken != null && !result.contains(certificateToken)) {
					result.add(certificateToken);
				}
			}
		}

		return result;
	}

	/**
	 * This method is used to identify the signing certificates (the certificate
	 * which didn't sign any other certificate)
	 * 
	 * @param certificates a collection of {@link CertificateToken}s
	 * @return the identified signing certificates
	 */
	private List<CertificateToken> getSigningCertificates(List<CertificateToken> certificates) {
		if (Utils.isCollectionEmpty(certificates)) {
			throw new DSSException("No signing certificate found");
		}
		
		List<CertificateToken> potentialSigners = new ArrayList<>();
		for (CertificateToken signer : certificates) {
			boolean caCert = false;

			for (CertificateToken token : certificates) {
				if (signer.getPublicKey().equals(token.getPublicKeyOfTheSigner())) {
					caCert = true;
					break;
				}
			}

			if (!caCert) {
				potentialSigners.add(signer);
			}
		}

		if (Utils.isCollectionEmpty(potentialSigners)) {
			throw new DSSException("The certificate chain contains only bridge certificates");
		}

		return potentialSigners;
	}

}
