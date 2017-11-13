/*******************************************************************************
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
 ******************************************************************************/
package eu.europa.esig.dss.signature.policy.validation.items;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.signature.policy.CertificateTrustPoint;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;

public class CertificateTrustPointValidator implements ItemValidator {

	private static final Logger LOG = LoggerFactory.getLogger(CertificateTrustPointValidator.class);
	
	private CertStore knownTrustStore;
	private CertificateTrustPoint trustPoint;
	private CertificatePool certPool;

	private Set<CertificateToken> chainCertificates = Collections.emptySet();

	private CertificateToken targetCertificate;


	public static Set<CertificateToken> buildKnownChain(CertificateToken target) {
		Set<CertificateToken> knownTrustStore = new LinkedHashSet<CertificateToken>();
		if (target != null) {
			knownTrustStore.add(target);
			for(CertificateToken issuerToken = target.getIssuerToken(); issuerToken != null; issuerToken = issuerToken.getIssuerToken()) {
				if (!issuerToken.isSelfSigned())
					knownTrustStore.add(issuerToken);
			}
		}
		return knownTrustStore;
	}

	public static CertStore buildCertStore(CertificateToken target, CertificatePool certPool) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		List<X509Certificate> knownTrustStore = new ArrayList<X509Certificate>();
		if (target != null) {
			knownTrustStore.add(target.getCertificate());
			for(CertificateToken issuerToken : certPool.getCertificateTokens()) {
				if (!issuerToken.isSelfSigned())
					knownTrustStore.add(issuerToken.getCertificate());
			}
		}
		CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(knownTrustStore));
		return store;
	}

	public CertificateTrustPointValidator(CertificatePool certPool, CertStore store, CertificateTrustPoint trustPoint, CertificateToken targetCertificate) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		this.trustPoint = trustPoint;
		this.certPool = certPool;
		this.knownTrustStore = store;
		this.targetCertificate = targetCertificate;
	}

	public CertificateTrustPointValidator(CertificatePool certPool, CertificateToken target, CertificateTrustPoint trustPoint) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		this.trustPoint = trustPoint;
		this.certPool = certPool;
		this.knownTrustStore = buildCertStore(target, certPool);
		this.targetCertificate = target;
	}
	
	public boolean validate() {
		try {
			CertPathBuilderResult build = buildCertPath();
			CertPath certPath = build.getCertPath();
			List<? extends Certificate> certificates = certPath.getCertificates();
			chainCertificates = new LinkedHashSet<CertificateToken>();
			boolean rootAdded = false;
			for (Certificate certificate : certificates) {
				CertificateToken certToken = getToken(certificate);
				if (certToken.isSelfSigned()) {
					// Only the root (trust point) comes from a trusted store, a.k.a., SignaturePolicy
					certToken = certPool.getInstance(certToken, CertificateSourceType.TRUSTED_STORE);
				}
				chainCertificates.add(certToken);
			}
			if (!rootAdded) {
				CertificateToken tk = getToken(trustPoint.getTrustpoint());
				chainCertificates.add(certPool.getInstance(tk, CertificateSourceType.TRUSTED_STORE));
			}
			return !chainCertificates.isEmpty();
		} catch (Exception e) {
			LOG.debug("Error on validating certTrustCondition", e);
		}
		return false;
	}

	private CertificateToken getToken(Certificate certificate) {
		X509Certificate x509Cert = (X509Certificate) certificate;
		List<CertificateToken> listCertificates = certPool.get(x509Cert.getSubjectX500Principal());
		CertificateToken certToken = listCertificates.size() > 0? listCertificates.get(0): new CertificateToken(x509Cert);
		return certToken;
	}

	private CertPathBuilderResult buildCertPath()
			throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
			CertPathBuilderException {
		Set<TrustAnchor> trustPoints = Collections.singleton(new TrustAnchor(trustPoint.getTrustpoint(), null));
		X509CertSelector certSelector = new X509CertSelector();
		certSelector.setPolicy(trustPoint.getAcceptablePolicySet());
		certSelector.setCertificate(targetCertificate.getCertificate());
		PKIXBuilderParameters buildParams = new PKIXBuilderParameters(trustPoints, certSelector);
		buildParams.setRevocationEnabled(false);
		buildParams.addCertStore(knownTrustStore);

		if (trustPoint.getPolicyConstraints() != null) {
			// TODO Add processing for other values
			if (trustPoint.getPolicyConstraints().getRequireExplicitPolicy() != null && trustPoint.getPolicyConstraints().getRequireExplicitPolicy() == 0) {
				buildParams.setExplicitPolicyRequired(true);
			}
			// TODO Improve processing for other values
			if (trustPoint.getPolicyConstraints().getInhibitPolicyMapping() != null && trustPoint.getPolicyConstraints().getInhibitPolicyMapping() == 0) {
				buildParams.setPolicyMappingInhibited(true);
			}
		}

		CertPathBuilder pathBuilder = CertPathBuilder.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
		CertPathBuilderResult result = pathBuilder.build(buildParams);
		
		// Since the value of MaxPathLength can be overriden by the value in the CA BasicConstraints
		int maxPathLength = trustPoint.getPathLenConstraint() == null? -1: trustPoint.getPathLenConstraint();
		if (maxPathLength >= 0 && result.getCertPath().getCertificates().size() > maxPathLength) {
			throw new DSSException("PathLenConstraint excedded");
		}
		
		// TODO check NameConstraints

		return result;
	}

	public Set<CertificateToken> getChainCertificates() {
		return Collections.unmodifiableSet(chainCertificates);
	}
	
	@Override
	public String getErrorDetail() {
		return null;
	}

}
