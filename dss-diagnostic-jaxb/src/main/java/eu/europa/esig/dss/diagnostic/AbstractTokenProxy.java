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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;

public abstract class AbstractTokenProxy implements TokenProxy {

	protected abstract XmlBasicSignature getCurrentBasicSignature();

	protected abstract List<XmlChainItem> getCurrentCertificateChain();

	protected abstract XmlSigningCertificate getCurrentSigningCertificate();

	@Override
	public List<XmlDigestMatcher> getDigestMatchers() {
		return Collections.emptyList();
	}

	@Override
	public List<CertificateWrapper> getCertificateChain() {
		List<CertificateWrapper> result = new ArrayList<CertificateWrapper>();
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
		return (basicSignature != null) && basicSignature.isSignatureIntact();
	}

	@Override
	public boolean isSignatureValid() {
		XmlBasicSignature basicSignature = getCurrentBasicSignature();
		return (basicSignature != null) && basicSignature.isSignatureValid();
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
	public boolean isIssuerSerialMatch() {
		XmlSigningCertificate currentSigningCertificate = getCurrentSigningCertificate();
		return (currentSigningCertificate != null)
				&& (currentSigningCertificate.isIssuerSerialMatch() != null && currentSigningCertificate.isIssuerSerialMatch());
	}

	@Override
	public boolean isAttributePresent() {
		XmlSigningCertificate currentSigningCertificate = getCurrentSigningCertificate();
		return (currentSigningCertificate != null)
				&& (currentSigningCertificate.isAttributePresent() != null && currentSigningCertificate.isAttributePresent());
	}

	@Override
	public boolean isDigestValueMatch() {
		XmlSigningCertificate currentSigningCertificate = getCurrentSigningCertificate();
		return (currentSigningCertificate != null)
				&& (currentSigningCertificate.isDigestValueMatch() != null && currentSigningCertificate.isDigestValueMatch());
	}

	@Override
	public boolean isDigestValuePresent() {
		XmlSigningCertificate currentSigningCertificate = getCurrentSigningCertificate();
		return (currentSigningCertificate != null)
				&& (currentSigningCertificate.isDigestValuePresent() != null && currentSigningCertificate.isDigestValuePresent());
	}

	@Override
	public CertificateWrapper getSigningCertificate() {
		XmlSigningCertificate currentSigningCertificate = getCurrentSigningCertificate();
		if (currentSigningCertificate != null) {
			return new CertificateWrapper(currentSigningCertificate.getCertificate());
		}
		return null;
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
			if (other.getId() != null)
				return false;
		} else if (!getId().equals(other.getId()))
			return false;
		return true;
	}

}
