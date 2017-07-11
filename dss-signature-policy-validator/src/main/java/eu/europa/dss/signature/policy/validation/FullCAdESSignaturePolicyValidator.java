package eu.europa.dss.signature.policy.validation;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.cms.CMSSignedData;

import eu.europa.dss.signature.policy.CertInfoReq;
import eu.europa.dss.signature.policy.CertRefReq;
import eu.europa.dss.signature.policy.CertificateTrustPoint;
import eu.europa.dss.signature.policy.CommitmentRule;
import eu.europa.dss.signature.policy.SignaturePolicy;
import eu.europa.dss.signature.policy.SignatureValidationPolicy;
import eu.europa.dss.signature.policy.SignerAndVerifierRules;
import eu.europa.dss.signature.policy.SignerRules;
import eu.europa.dss.signature.policy.asn1.ASN1SignaturePolicy;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.x509.CertificateToken;

public class FullCAdESSignaturePolicyValidator extends BasicCAdESSignaturePolicyValidator {

	private Map<String, String> errors = new HashMap<String, String>();
	
	private List<? extends Certificate> signerCertPath = null;

	public FullCAdESSignaturePolicyValidator(SignaturePolicyProvider signaturePolicyProvider, CAdESSignature sig) {
		super(signaturePolicyProvider, sig);
	}

	@Override
	public Map<String, String> validate() {
		// the upper class validates the hash of the policy in the declared attribute and the value in the policy itself
		errors.putAll(super.validate());
		
		if (getSignaturePolicy() != null && getSignaturePolicy().getPolicyContent() != null) {
			validateSignaturePolicyCommitmentRules();
		}
		
		return errors;
	}

	private SignaturePolicy parse() {
		SignaturePolicy sigPolicy = null;
		try (
			InputStream is = getSignaturePolicy().getPolicyContent().openStream();
			ASN1InputStream asn1is = new ASN1InputStream(is);
		) {
			ASN1Primitive asn1SP = asn1is.readObject();
			if (asn1SP == null) {
				throw new DSSException("Error reading signature policy: no content");
			}
			sigPolicy = ASN1SignaturePolicy.getInstance(asn1SP);
		} catch (DSSException e) {
			throw e;
		} catch (IOException e) {
			// If the sigPolicy was loaded successfully, don't bubble up the error on stream close
			if (sigPolicy == null) {
				throw new DSSException("Error reading signature policy", e);
			}
		}
		return sigPolicy;
	}

	/**
	 * Validates signature based on a signature policy. It should not be called if
	 * No explicit signature police was declared upon signing.
	 */
	private void validateSignaturePolicyCommitmentRules() {
		CommitmentRule cmmtRule = findCommitmentRule(cadesSignature.getCommitmentTypeIndication() == null? null: cadesSignature.getCommitmentTypeIndication().getIdentifiers());
		
		try {
			setupCertificatePath(cmmtRule);
		} catch (Exception e) {
			throw new DSSException("Unkown error on signerCert path building", e);
		}
		validateSignerAndVeriferRules(cmmtRule.getSignerAndVeriferRules());
	}

	private void validateSignerAndVeriferRules(SignerAndVerifierRules signerAndVeriferRules) {
		SignerRules signerRules = signerAndVeriferRules.getSignerRules();
		
		validateSignerRules(signerRules);
	}
	
	public void setupCertificatePath(CommitmentRule cmmtRule) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, CertPathBuilderException, CertificateEncodingException {
		CertificateToken signingCertificate = cadesSignature.getSigningCertificateToken();
		if (signingCertificate == null) {
			signerCertPath = new ArrayList<X509Certificate>();
			return;
		}
		
		Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
		if (cmmtRule.getSigningCertTrustCondition().getSignerTrustTrees() != null && 
				cmmtRule.getSigningCertTrustCondition().getSignerTrustTrees().getCertificateTrustPoints() != null) {
			for(CertificateTrustPoint ctp : cmmtRule.getSigningCertTrustCondition().getSignerTrustTrees().getCertificateTrustPoints()) {
				trustAnchors.add(new TrustAnchor(ctp.getTrustpoint(), ctp.getNameConstraints() == null? null: ctp.getNameConstraints().getEncoded()));
			}
		}			
		
		signerCertPath = getCertificateFullPath(signingCertificate, trustAnchors);
	}

	public static List<? extends Certificate> getCertificateFullPath(CertificateToken signingCertificate, Set<TrustAnchor> trustAnchors)
			throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
			CertPathBuilderException {
		X509CertSelector certSelector = new X509CertSelector();
		certSelector.setCertificate(signingCertificate.getCertificate());
		certSelector.setSubject(signingCertificate.getSubjectX500Principal());
		
		List<X509Certificate> interCerts = new ArrayList<X509Certificate>();
		interCerts.add(signingCertificate.getCertificate());
		for(CertificateToken issuerToken = signingCertificate.getIssuerToken(); issuerToken != null; issuerToken = issuerToken.getIssuerToken()) {
			interCerts.add(issuerToken.getCertificate());
		}
		CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(interCerts));

		PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, certSelector);
		params.setRevocationEnabled(false);
		params.addCertStore(store);
		
        CertPathBuilder pathBuilder = CertPathBuilder.getInstance("PKIX", "BC");
        CertPath certPath = pathBuilder.build(params).getCertPath();
		return certPath.getCertificates();
	}

	private void validateSignerRules(SignerRules signerRules) {
		CMSSignedData cmsSignedData = cadesSignature.getCmsSignedData();
		
		validateSignerRuleExternalData(signerRules.getExternalSignedData(), cmsSignedData);
		validateSignerRuleMandatedSignedAttr(signerRules.getMandatedSignedAttr(), cmsSignedData);
		validateSignerRuleMandatedUnsignedAttr(signerRules.getMandatedUnsignedAttr(), cmsSignedData);
		validateSignerRuleMandatedCertificateRef(signerRules.getMandatedCertificateRef(), cmsSignedData);
		validateSignerRuleMandatedCertificateInfo(signerRules.getMandatedCertificateInfo(), cmsSignedData);
	}

	private void validateSignerRuleExternalData(Boolean externalSignedData, CMSSignedData cmsSignedData) {
		if (externalSignedData != null) {
			if (!(cmsSignedData.getSignedContent().getContent() == null ^ externalSignedData)) {
				errors.put("signerRules.externalSignedData", "Expected to be: " + externalSignedData);
			}
		}
	}

	private void validateSignerRuleMandatedSignedAttr(List<String> mandatedSignedAttr, CMSSignedData cmsSignedData) {
		if (mandatedSignedAttr == null || !mandatedSignedAttr.isEmpty()) {
			return;
		}
		List<String> attributesMissing = new ArrayList<>();
		for (String oid : mandatedSignedAttr) {
			if (CMSUtils.getSignedAttributes(cadesSignature.getSignerInformation()).get(new ASN1ObjectIdentifier(oid)) == null) {
				attributesMissing.add(oid);
			}
		}
		
		if (!attributesMissing.isEmpty()) {
			errors.put("signerRules.mandatedSignedAttr", "Signed attributes missing: "+attributesMissing);
		}
	}

	private void validateSignerRuleMandatedUnsignedAttr(List<String> mandatedUnsignedAttr,
			CMSSignedData cmsSignedData) {
		if (mandatedUnsignedAttr == null || !mandatedUnsignedAttr.isEmpty()) {
			return;
		}
		List<String> attributesMissing = new ArrayList<>();
		for (String oid : mandatedUnsignedAttr) {
			if (CMSUtils.getSignedAttributes(cadesSignature.getSignerInformation()).get(new ASN1ObjectIdentifier(oid)) == null) {
				attributesMissing.add(oid);
			}
		}
		
		if (!attributesMissing.isEmpty()) {
			errors.put("signerRules.mandatedUnsignedAttr", "Unsigned attributes missing: "+attributesMissing);
		}
	}

	/**
	 *    The mandatedCertificateRef identifies:
	 *       *  whether a signer's certificate, or all certificates in the
	 *          certification path to the trust point must be by the signer in
	 *          the *  certificates field of SignedData.
	 * @param mandatedCertificateRef
	 * @param cmsSignedData
	 */
	private void validateSignerRuleMandatedCertificateRef(CertRefReq mandatedCertificateRef,
			CMSSignedData cmsSignedData) {
		if (mandatedCertificateRef == null) {
			mandatedCertificateRef = CertRefReq.signerOnly;
		}
		
		boolean foundSignerCert = cadesSignature.getSigningCertificateToken() != null;
		
		if (!foundSignerCert) {
			errors.put("signerRules.mandatedCertificateRef", "No signing certificate reference found");
			return;
		}
		
		boolean foundAdditionalCert = cadesSignature.getCertificateSource().getKeyInfoCertificates().size() > 1;
		if (mandatedCertificateRef == CertRefReq.signerOnly) {
			if (foundAdditionalCert) {
				errors.put("signerRules.mandatedCertificateRef", "Found more certificate references than expected");
				return;
			}
		}
		
		if (mandatedCertificateRef == CertRefReq.fullPath) {
			if (!foundAdditionalCert || !containsFullChain(cadesSignature.getCertificateSource().getKeyInfoCertificates())) {
				errors.put("signerRules.mandatedCertificateRef", "Found less references than expected");
			}
		}
			
	}

	private boolean containsFullChain(List<CertificateToken> certificates) {
		if (certificates == null || certificates.size() <= signerCertPath.size()) {
			return false;
		}
		
		for (Certificate cert : signerCertPath) {
			if (!certificates.contains(new CertificateToken((X509Certificate) cert))) {
				return false;
			}
		}
		
		return true;
	}

	private void validateSignerRuleMandatedCertificateInfo(CertInfoReq mandatedCertificateInfo, CMSSignedData cmsSignedData) {
		if (mandatedCertificateInfo == null) {
			mandatedCertificateInfo = CertInfoReq.none;
		}
		
		Collection<CertificateToken> certificates = cadesSignature.getCertificateSource().getKeyInfoCertificates();
		if (mandatedCertificateInfo == CertInfoReq.none) {
			if (certificates.isEmpty()) {
				errors.put("signerRules.mandatedCertificateInfo", "Should not have any certificates in the signature");
			}
		} else {
			if (cadesSignature.getSigningCertificateToken() == null || certificates.contains(cadesSignature.getSigningCertificateToken())) {
				errors.put("signerRules.mandatedCertificateInfo", "Missing certificates in the signature");
			} else if (mandatedCertificateInfo == CertInfoReq.signerOnly && certificates.size() != 1) {
				errors.put("signerRules.mandatedCertificateInfo", "Should have only the signer certificate in the signature");
			} else if (mandatedCertificateInfo == CertInfoReq.fullPath && !containsFullChain(cadesSignature.getCertificateSource().getKeyInfoCertificates())) {
				errors.put("signerRules.mandatedCertificateInfo", "Should have the signer certificate full path in the signature");
			}
		}
	}

	public CommitmentRule findCommitmentRule(List<String> identifiers) {
		SignatureValidationPolicy signatureValidationPolicy = getSignatureValidationPolicy();
		for (CommitmentRule cmmtRule : signatureValidationPolicy.getCommitmentRules()) {
			if (identifiers == null || identifiers.isEmpty()) {
				if (cmmtRule.getSelCommitmentTypes().contains(null)) {
					return new CommitmentRuleWrapper(cmmtRule, signatureValidationPolicy.getCommonRules()) ;
				}
			} else {
				for (String oid : identifiers) {
					if (cmmtRule.getSelCommitmentTypes().contains(oid)) {
						return new CommitmentRuleWrapper(cmmtRule, signatureValidationPolicy.getCommonRules()); 
					}
				}
			}
		}
		
		// RFC 3125
		// "... the electronic signature must contain a commitment type indication
		// that must fit one of the commitments types that are mentioned in
		// CommitmentType."
		throw new DSSException("The commitment type used was not found");
	}

	public SignatureValidationPolicy getSignatureValidationPolicy() {
		SignaturePolicy policy = parse();
		SignatureValidationPolicy signatureValidationPolicy = policy.getSignPolicyInfo().getSignatureValidationPolicy();
		return signatureValidationPolicy;
	}
	
}
