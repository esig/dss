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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * An abstract representation of a validation object
 *
 */
public abstract class AbstractTokenProxy implements TokenProxy {

	/**
	 * Default constructor
	 */
	protected AbstractTokenProxy() {
		// empty
	}

	/**
	 * Returns a basic signature validation
	 *
	 * @return {@link XmlBasicSignature}
	 */
	protected abstract XmlBasicSignature getCurrentBasicSignature();

	/**
	 * Returns the token's certificate chain
	 *
	 * @return a list of {@link XmlChainItem}s
	 */
	protected abstract List<XmlChainItem> getCurrentCertificateChain();

	/**
	 * Returns the signing certificate of the token
	 *
	 * @return {@link XmlSigningCertificate}
	 */
	protected abstract XmlSigningCertificate getCurrentSigningCertificate();

	@Override
	public FoundCertificatesProxy foundCertificates() {
		return new FoundCertificatesProxy(null);
	}

	@Override
	public FoundRevocationsProxy foundRevocations() {
		return new FoundRevocationsProxy(null);
	}

	@Override
	public List<XmlDigestMatcher> getDigestMatchers() {
		return Collections.emptyList();
	}

	@Override
	public List<CertificateWrapper> getCertificateChain() {
		List<CertificateWrapper> result = new ArrayList<>();
		List<XmlChainItem> certificateChain = getCurrentCertificateChain();
		if (certificateChain != null) {
			for (XmlChainItem xmlChainCertificate : certificateChain) {
				if (xmlChainCertificate.getCertificate() != null) {
					result.add(new CertificateWrapper(xmlChainCertificate.getCertificate()));
				}
			}
		}
		return result;
	}

	@Override
	public boolean isSignatureIntact() {
		XmlBasicSignature basicSignature = getCurrentBasicSignature();
		if (basicSignature != null) {
			Boolean signatureIntact = basicSignature.isSignatureIntact();
			return signatureIntact != null && signatureIntact;
		}
		return false;
	}

	@Override
	public boolean isSignatureValid() {
		XmlBasicSignature basicSignature = getCurrentBasicSignature();
		if (basicSignature != null) {
			Boolean signatureValid = basicSignature.isSignatureValid();
			return signatureValid != null && signatureValid;
		}
		return false;
	}

	@Override
	public SignatureAlgorithm getSignatureAlgorithm() {
		EncryptionAlgorithm encryptionAlgorithm = getEncryptionAlgorithm();
		DigestAlgorithm digestAlgorithm = getDigestAlgorithm();
		if (encryptionAlgorithm != null && digestAlgorithm != null) {
			return SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digestAlgorithm);
		}
		return null;
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() {
		XmlBasicSignature basicSignature = getCurrentBasicSignature();
		if (basicSignature != null) {
			return basicSignature.getEncryptionAlgoUsedToSignThisToken();
		}
		return null;
	}

	@Override
	public DigestAlgorithm getDigestAlgorithm() {
		XmlBasicSignature basicSignature = getCurrentBasicSignature();
		if (basicSignature != null) {
			return basicSignature.getDigestAlgoUsedToSignThisToken();
		}
		return null;
	}

	@Override
	public String getKeyLengthUsedToSignThisToken() {
		XmlBasicSignature basicSignature = getCurrentBasicSignature();
		if (basicSignature != null) {
			return basicSignature.getKeyLengthUsedToSignThisToken();
		}
		return "";
	}

	@Override
	public CertificateWrapper getSigningCertificate() {
		XmlSigningCertificate currentSigningCertificate = getCurrentSigningCertificate();
		if (currentSigningCertificate != null && currentSigningCertificate.getCertificate() != null) {
			return new CertificateWrapper(currentSigningCertificate.getCertificate());
		}
		return null;
	}
	
	@Override
	public byte[] getSigningCertificatePublicKey() {
		XmlSigningCertificate currentSigningCertificate = getCurrentSigningCertificate();
		if (currentSigningCertificate != null) {
			return currentSigningCertificate.getPublicKey();
		}
		return null;
	}
	
	@Override
	public boolean isSigningCertificateReferencePresent() {
		return !getSigningCertificateReferences().isEmpty();
	}
	
	@Override
	public boolean isSigningCertificateReferenceUnique() {
		return getSigningCertificateReferences().size() == 1;
	}
	
	@Override
	public CertificateRefWrapper getSigningCertificateReference() {
		List<CertificateRefWrapper> signingCertificateReferences = foundCertificates()
				.getRelatedCertificateRefsByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
		if (!signingCertificateReferences.isEmpty()) {
			// return a reference matching a signing certificate
			CertificateWrapper signingCertificate = getSigningCertificate();
			if (signingCertificate != null) {
				return getCertificateReferenceOfReferenceOriginType(signingCertificate, CertificateRefOrigin.SIGNING_CERTIFICATE);
			}

		} else {
			List<CertificateRefWrapper> orphanSigningCertificateReferences = foundCertificates()
					.getOrphanCertificateRefsByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
			if (!orphanSigningCertificateReferences.isEmpty()) {
				return orphanSigningCertificateReferences.iterator().next();
			}
		}
		return null;
	}

	private CertificateRefWrapper getCertificateReferenceOfReferenceOriginType(CertificateWrapper certificate,
																			   CertificateRefOrigin refOrigin) {
		for (RelatedCertificateWrapper relatedCertificate : foundCertificates().getRelatedCertificates()) {
			List<CertificateRefWrapper> signCertRefs = relatedCertificate.getReferences();
			if (certificate.getId().equals(relatedCertificate.getId()) && !signCertRefs.isEmpty()) {
				for (CertificateRefWrapper signCertRef : signCertRefs) {
					if (refOrigin.equals(signCertRef.getOrigin())) {
						return signCertRef;
					}
				}
			}
		}
		return null;
	}
	
	@Override
	public List<CertificateRefWrapper> getSigningCertificateReferences() {
		List<CertificateRefWrapper> certificateRefs = new ArrayList<>();
		certificateRefs.addAll(foundCertificates().getRelatedCertificateRefsByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE));
		certificateRefs.addAll(foundCertificates().getOrphanCertificateRefsByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE));
		return certificateRefs;
	}

	@Override
	public boolean isTrustedChain() {
		List<CertificateWrapper> certificateChain = getCertificateChain();
		for (CertificateWrapper certificate : certificateChain) {
			if (certificate.isTrusted()) {
				return true;
			}
		}
		return false;
	}
	
	/**
	 * Checks if the certificate chain is trusted from a Trusted Store
	 * NOTE: Not from Trusted List!
	 *
	 * @return TRUE if a certificate chain is trusted from a trusted store, FALSE otherwise
	 */
	public boolean isCertificateChainFromTrustedStore() {
		for (CertificateWrapper certificate : getCertificateChain()) {
			if (certificate.getSources().contains(CertificateSourceType.TRUSTED_STORE)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns binaries of the token, when present
	 *
	 * @return a byte array
	 */
	public abstract byte[] getBinaries();
	
	@Override
	public String toString() {
		return "Token Id='" + getId() + "'";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((getId() == null) ? 0 : getId().hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		AbstractTokenProxy other = (AbstractTokenProxy) obj;
		if (getId() == null) {
			return other.getId() == null;
		} else return getId().equals(other.getId());
	}

}
