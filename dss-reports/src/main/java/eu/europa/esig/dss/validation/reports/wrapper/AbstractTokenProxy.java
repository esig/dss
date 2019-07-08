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
package eu.europa.esig.dss.validation.reports.wrapper;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificate;
import eu.europa.esig.dss.utils.Utils;

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
		if (Utils.isCollectionNotEmpty(certificateChain)) {
			for (XmlChainItem xmlChainCertificate : certificateChain) {
				result.add(new CertificateWrapper(xmlChainCertificate.getCertificate()));
			}
		}
		return result;
	}

	@Override
	public boolean isSignatureIntact() {
		XmlBasicSignature basicSignature = getCurrentBasicSignature();
		return (basicSignature != null) && Utils.isTrue(basicSignature.isSignatureIntact());
	}

	@Override
	public boolean isSignatureValid() {
		XmlBasicSignature basicSignature = getCurrentBasicSignature();
		return (basicSignature != null) && Utils.isTrue(basicSignature.isSignatureValid());
	}

	@Override
	public String getDigestAlgoUsedToSignThisToken() {
		XmlBasicSignature basicSignature = getCurrentBasicSignature();
		if (basicSignature != null) {
			return basicSignature.getDigestAlgoUsedToSignThisToken();
		}
		return Utils.EMPTY_STRING;
	}

	@Override
	public DigestAlgorithm getDigestAlgorithm() {
		String signatureDigestAlgorithmName = getDigestAlgoUsedToSignThisToken();
		return DigestAlgorithm.forName(signatureDigestAlgorithmName, null);
	}

	@Override
	public String getEncryptionAlgoUsedToSignThisToken() {
		XmlBasicSignature basicSignature = getCurrentBasicSignature();
		if (basicSignature != null) {
			return basicSignature.getEncryptionAlgoUsedToSignThisToken();
		}
		return Utils.EMPTY_STRING;
	}

	@Override
	public String getMaskGenerationFunctionUsedToSignThisToken() {
		XmlBasicSignature basicSignature = getCurrentBasicSignature();
		if (basicSignature != null) {
			return basicSignature.getMaskGenerationFunctionUsedToSignThisToken();
		}
		return Utils.EMPTY_STRING;
	}

	@Override
	public MaskGenerationFunction getMaskGenerationFunction() {
		String mgf = getMaskGenerationFunctionUsedToSignThisToken();
		return MaskGenerationFunction.valueOf(mgf);
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() {
		String encryptionAlgoUsedToSignThisToken = getEncryptionAlgoUsedToSignThisToken();
		return EncryptionAlgorithm.forName(encryptionAlgoUsedToSignThisToken, null);
	}

	@Override
	public String getKeyLengthUsedToSignThisToken() {
		XmlBasicSignature basicSignature = getCurrentBasicSignature();
		if (basicSignature != null) {
			return basicSignature.getKeyLengthUsedToSignThisToken();
		}
		return Utils.EMPTY_STRING;
	}

	@Override
	public boolean isIssuerSerialMatch() {
		XmlSigningCertificate currentSigningCertificate = getCurrentSigningCertificate();
		return (currentSigningCertificate != null) && Utils.isTrue(currentSigningCertificate.isIssuerSerialMatch());
	}

	@Override
	public boolean isAttributePresent() {
		XmlSigningCertificate currentSigningCertificate = getCurrentSigningCertificate();
		return (currentSigningCertificate != null) && Utils.isTrue(currentSigningCertificate.isAttributePresent());
	}

	@Override
	public boolean isDigestValueMatch() {
		XmlSigningCertificate currentSigningCertificate = getCurrentSigningCertificate();
		return (currentSigningCertificate != null) && Utils.isTrue(currentSigningCertificate.isDigestValueMatch());
	}

	@Override
	public boolean isDigestValuePresent() {
		XmlSigningCertificate currentSigningCertificate = getCurrentSigningCertificate();
		return (currentSigningCertificate != null) && Utils.isTrue(currentSigningCertificate.isDigestValuePresent());
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
