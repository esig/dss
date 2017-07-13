package eu.europa.dss.signature.policy.validation;

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
import java.util.List;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.dss.signature.policy.CertificateTrustPoint;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;

public class CertificateTrustPointValidator {

	private static final Logger LOG = LoggerFactory.getLogger(CertificateTrustPointValidator.class);
	
	private CertStore knownTrustStore;
	private CertificateTrustPoint trustPoint;
	private CertificatePool certPool;

	private List<CertificateToken> chainCertificates = Collections.emptyList();


	public static List<CertificateToken> buildKnownChain(CertificateToken target) {
		List<CertificateToken> knownTrustStore = new ArrayList<CertificateToken>();
		knownTrustStore.add(target);
		for(CertificateToken issuerToken = target.getIssuerToken(); issuerToken != null; issuerToken = issuerToken.getIssuerToken()) {
			if (!issuerToken.isSelfSigned())
				knownTrustStore.add(issuerToken);
		}
		return knownTrustStore;
	}

	public static CertStore buildCertStore(CertificateToken target, CertificatePool certPool) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		List<X509Certificate> knownTrustStore = new ArrayList<X509Certificate>();
		knownTrustStore.add(target.getCertificate());
		for(CertificateToken issuerToken : certPool.getCertificateTokens()) {
			if (!issuerToken.isSelfSigned())
				knownTrustStore.add(issuerToken.getCertificate());
		}
		CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(knownTrustStore));
		return store;
	}

	public CertificateTrustPointValidator(CertificatePool certPool, CertStore store, CertificateTrustPoint trustPoint) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		this.trustPoint = trustPoint;
		this.certPool = certPool;
		this.knownTrustStore = store;
	}

	public CertificateTrustPointValidator(CertificatePool certPool, CertificateToken target, CertificateTrustPoint trustPoint) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		this.trustPoint = trustPoint;
		this.certPool = certPool;
		this.knownTrustStore = buildCertStore(target, certPool);
	}
	
	public boolean validate() {
		try {
			CertPathBuilderResult build = buildCertPath(knownTrustStore, trustPoint);
			CertPath certPath = build.getCertPath();
			List<? extends Certificate> certificates = certPath.getCertificates();
			chainCertificates = new ArrayList<CertificateToken>();
			for (Certificate certificate : certificates) {
				CertificateToken certToken = new CertificateToken((X509Certificate) certificate);
				if (certToken.isSelfSigned()) {
					// Only the root (trust point) comes from a trusted store, a.k.a., SignaturePolicy
					certToken = certPool.getInstance(certToken, CertificateSourceType.TRUSTED_STORE);
				}
				chainCertificates.add(certToken);
			}
			return !chainCertificates.isEmpty();
		} catch (Exception e) {
			LOG.debug("Error on validating certTrustCondition", e);
		}
		return false;
	}

	private CertPathBuilderResult buildCertPath(CertStore store, CertificateTrustPoint trustPoint)
			throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
			CertPathBuilderException {
		X509CertSelector certSelector = new X509CertSelector();
		Set<TrustAnchor> trustPoints = Collections.singleton(new TrustAnchor(trustPoint.getTrustpoint(), trustPoint.getNameConstraints() == null? null: trustPoint.getNameConstraints().getEncoded()));
		certSelector.setPolicy(trustPoint.getAcceptablePolicySet());
		PKIXBuilderParameters buildParams = new PKIXBuilderParameters(trustPoints, certSelector);
		buildParams.setRevocationEnabled(false);
		buildParams.addCertStore(store);
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
		return result;
	}

	public List<CertificateToken> getChainCertificates() {
		return Collections.unmodifiableList(chainCertificates);
	}

}
