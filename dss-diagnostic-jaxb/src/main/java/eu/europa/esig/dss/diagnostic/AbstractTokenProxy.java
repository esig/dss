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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModificationDetection;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;

public abstract class AbstractTokenProxy implements TokenProxy {

	protected abstract XmlBasicSignature getCurrentBasicSignature();

	protected abstract List<XmlChainItem> getCurrentCertificateChain();

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
				result.add(new CertificateWrapper(xmlChainCertificate.getCertificate()));
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
	public MaskGenerationFunction getMaskGenerationFunction() {
		XmlBasicSignature basicSignature = getCurrentBasicSignature();
		if (basicSignature != null) {
			return basicSignature.getMaskGenerationFunctionUsedToSignThisToken();
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
		return getSigningCertificateReferences().size() > 0;
	}
	
	@Override
	public boolean isSigningCertificateReferenceUnique() {
		return getSigningCertificateReferences().size() == 1;
	}
	
	@Override
	public CertificateRefWrapper getSigningCertificateReference() {
		List<CertificateRefWrapper> signingCertificateReferences = foundCertificates()
				.getRelatedCertificateRefsByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
		if (signingCertificateReferences.size() > 0) {
			// return a reference matching a signing certificate
			CertificateWrapper signingCertificate = getSigningCertificate();
			if (signingCertificate != null) {
				for (RelatedCertificateWrapper relatedCertificate : foundCertificates().getRelatedCertificates()) {
					if (signingCertificate.getId().equals(relatedCertificate.getId()) && relatedCertificate.getReferences().size() > 0) {
						return relatedCertificate.getReferences().iterator().next();
					}
				}
			}
		} else {
			List<CertificateRefWrapper> orphanSigningCertificateReferences = foundCertificates()
					.getOrphanCertificateRefsByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
			if (orphanSigningCertificateReferences.size() > 0) {
				return orphanSigningCertificateReferences.iterator().next();
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
			List<CertificateSourceType> currentCertSources = certificate.getSources();
			if (currentCertSources.contains(CertificateSourceType.TRUSTED_STORE) || 
					currentCertSources.contains(CertificateSourceType.TRUSTED_LIST)) {
				return true;
			}
		}
		return false;
	}
	
	public boolean isCertificateChainFromTrustedStore() {
		for (CertificateWrapper certificate : getCertificateChain()) {
			if (certificate.getSources().contains(CertificateSourceType.TRUSTED_STORE)) {
				return true;
			}
		}
		return false;
	}

	public abstract byte[] getBinaries();
	
	protected boolean arePdfModificationsDetected(XmlPDFRevision pdfRevision) {
		if (pdfRevision != null) {
			XmlModificationDetection modificationDetection = pdfRevision.getModificationDetection();
			if (modificationDetection != null) {
				return modificationDetection.getAnnotationOverlap().size() != 0 || modificationDetection.getVisualDifference().size() != 0;
			}
		}
		return false;
	}
	
	protected List<BigInteger> getPdfAnnotationsOverlapConcernedPages(XmlPDFRevision pdfRevision) {
		if (pdfRevision != null) {
			XmlModificationDetection modificationDetection = pdfRevision.getModificationDetection();
			if (modificationDetection != null) {
				List<XmlModification> annotationOverlap = modificationDetection.getAnnotationOverlap();
				return getConcernedPages(annotationOverlap);
			}
		}
		return Collections.emptyList();
	}
	
	protected List<BigInteger> getPdfVisualDifferenceConcernedPages(XmlPDFRevision pdfRevision) {
		if (pdfRevision != null) {
			XmlModificationDetection modificationDetection = pdfRevision.getModificationDetection();
			if (modificationDetection != null) {
				List<XmlModification> visualDifference = modificationDetection.getVisualDifference();
				return getConcernedPages(visualDifference);
			}
		}
		return Collections.emptyList();
	}
	
	protected List<BigInteger> getPdfPageDifferenceConcernedPages(XmlPDFRevision pdfRevision) {
		if (pdfRevision != null) {
			XmlModificationDetection modificationDetection = pdfRevision.getModificationDetection();
			if (modificationDetection != null) {
				List<XmlModification> pageDifference = modificationDetection.getPageDifference();
				return getConcernedPages(pageDifference);
			}
		}
		return Collections.emptyList();
	}
	
	private List<BigInteger> getConcernedPages(List<XmlModification> xmlModifications) {
		List<BigInteger> pages = new ArrayList<>();
		for (XmlModification modification : xmlModifications) {
			pages.add(modification.getPage());
		}
		return pages;
	}
	
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
			if (other.getId() != null) {
				return false;
			}
		} else if (!getId().equals(other.getId())) {
			return false;
		}
		return true;
	}

}
