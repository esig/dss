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
		X509CertSelector certSelector = new X509CertSelector();
		Set<TrustAnchor> trustPoints = Collections.singleton(new TrustAnchor(trustPoint.getTrustpoint(), null));
		certSelector.setPolicy(trustPoint.getAcceptablePolicySet());
		//certSelector.setNameConstraints(trustPoint.getNameConstraints() == null? null: trustPoint.getNameConstraints().getEncoded());
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
