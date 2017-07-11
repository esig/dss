package eu.europa.dss.signature.policy.validation;

import java.io.IOException;
import java.io.InputStream;
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
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.dss.signature.policy.CertInfoReq;
import eu.europa.dss.signature.policy.CertRefReq;
import eu.europa.dss.signature.policy.CertRevReq;
import eu.europa.dss.signature.policy.CertificateTrustPoint;
import eu.europa.dss.signature.policy.CertificateTrustTrees;
import eu.europa.dss.signature.policy.CommitmentRule;
import eu.europa.dss.signature.policy.EnuRevReq;
import eu.europa.dss.signature.policy.RevReq;
import eu.europa.dss.signature.policy.SignaturePolicy;
import eu.europa.dss.signature.policy.SignatureValidationPolicy;
import eu.europa.dss.signature.policy.SignerAndVerifierRules;
import eu.europa.dss.signature.policy.SignerRules;
import eu.europa.dss.signature.policy.SigningCertTrustCondition;
import eu.europa.dss.signature.policy.asn1.ASN1SignaturePolicy;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.x509.CertificateToken;

public class FullCAdESSignaturePolicyValidator extends BasicCAdESSignaturePolicyValidator {

	private static final Logger LOG = LoggerFactory.getLogger(FullCAdESSignaturePolicyValidator.class);

	private Map<String, String> errors = new HashMap<String, String>();
	
	private List<? extends Certificate> signerCertPath = null;

	public FullCAdESSignaturePolicyValidator(SignaturePolicyProvider signaturePolicyProvider, CAdESSignature sig) {
		super(signaturePolicyProvider, sig);
	}

	@Override
	public Map<String, String> validate() {
		//  Upper class initializes the signature policy and validates the hash of the policy in 
		// the declared attribute and the value in the policy itself
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
		
		validateSigningCertTrustContition(cmmtRule.getSigningCertTrustCondition());
		validateSignerAndVeriferRules(cmmtRule.getSignerAndVeriferRules());
	}

	private void validateSigningCertTrustContition(SigningCertTrustCondition signingCertTrustCondition) {
		try {
			signerCertPath = validateCertTrustContition("signingCertTrustCondition", cadesSignature.getSigningCertificateToken(), signingCertTrustCondition.getSignerTrustTrees(), signingCertTrustCondition.getSignerRevReq());
		} catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | IOException e) {
			errors.put("signingCertTrustCondition", "unexpected error");
			LOG.warn("Error on validating signingCertTrustCondition", e);
		}
	}
	
	protected List<? extends Certificate> validateCertTrustContition(String label, CertificateToken certificate, CertificateTrustTrees certificateTrustTrees, CertRevReq certRevReq) throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		List<X509Certificate> interCerts = new ArrayList<X509Certificate>();
		if(isRevoked(certificate.getCertificate(), certRevReq.getEndCertRevReq())) {
			errors.put(label + ".certRevReq.endCertRevReq", "the endCert is revoked");
		}
		interCerts.add(certificate.getCertificate());
		for(CertificateToken issuerToken = certificate.getIssuerToken(); issuerToken != null; issuerToken = issuerToken.getIssuerToken()) {
			if (!issuerToken.isSelfSigned())
				interCerts.add(issuerToken.getCertificate());
		}
		if (certificateTrustTrees == null || certificateTrustTrees.getCertificateTrustPoints() == null) {
			return interCerts;
		}
		
		CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(interCerts));
		for (CertificateTrustPoint trustPoint : certificateTrustTrees.getCertificateTrustPoints()) {
			try {
				CertPathBuilderResult build = buildCertPath(store, trustPoint);
				CertPath certPath = build.getCertPath();
				List<? extends Certificate> chainCertificates = certPath.getCertificates();
				if (!chainCertificates.isEmpty()) {
					for (Certificate chainCertificate : chainCertificates) {
						if (chainCertificate.equals(certificate.getCertificate())) {
							// ignoring end cert
							continue;
						}
						
						if (isRevoked((X509Certificate) chainCertificate, certRevReq.getCaCerts())) {
							errors.put(label + ".certRevReq.cacerts", "At least one of the CA certificates is revoked");
							break;
						}
					}
					
					return chainCertificates;
				}
			} catch (Exception e) {
				LOG.debug("Error on validating certTrustCondition", e);
			}
		}
		return Collections.emptyList();
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
		buildParams.setMaxPathLength(trustPoint.getPathLenConstraint() == null? 0: trustPoint.getPathLenConstraint());
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
		CertPathBuilderResult build = pathBuilder.build(buildParams);
		return build;
	}

	private boolean isRevoked(X509Certificate certificate, RevReq revReq) {
		if (revReq.getEnuRevReq() == EnuRevReq.noCheck) {
			return true;
		}
		if (revReq.getEnuRevReq() == EnuRevReq.other) {
			// Only CRL/OCSP are supported
			return false;
		}
		
		if (revReq.getEnuRevReq() != EnuRevReq.ocspCheck) {
			try {
				if (isRevokedOcsp(certificate)) {
					return true;
				}
				
				if (revReq.getEnuRevReq() == EnuRevReq.eitherCheck) {
					return false;
				}
			} catch (Exception e) {
				LOG.debug("Unexpected error while checking OCSP", e);
				if (revReq.getEnuRevReq() != EnuRevReq.bothCheck) {
					return true;
				}
			}
		}

		if (revReq.getEnuRevReq() != EnuRevReq.crlCheck) {
			try {
				if (isRevokedCrl(certificate)) {
					return true;
				}
			} catch (Exception e) {
				LOG.debug("Unexpected error while checking CRL", e);
			}
		}
		
		return false;
	}

	private boolean isRevokedOcsp(X509Certificate certificate) {
		// TODO Check existing revoked information before downloading
		return false;
	}

	private boolean isRevokedCrl(X509Certificate certificate) {
		// TODO Check existing revoked information before downloading
		return false;
	}

	private void validateSignerAndVeriferRules(SignerAndVerifierRules signerAndVeriferRules) {
		SignerRules signerRules = signerAndVeriferRules.getSignerRules();
		
		validateSignerRules(signerRules);
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
		
 		boolean foundSignerCert = false;
 		boolean foundIssuingCert = false;
 		X509Certificate signingCert = cadesSignature.getSigningCertificateToken().getCertificate();
 		X509Certificate issuingCert = cadesSignature.getSigningCertificateToken().getIssuerToken() == null? null: cadesSignature.getSigningCertificateToken().getIssuerToken().getCertificate();
 
 		IssuerSerial signerCertIssuerSerial = new IssuerSerial(GeneralNames.getInstance(signingCert.getIssuerX500Principal().getEncoded()), signingCert.getSerialNumber());
 		IssuerSerial issuingCertIssuerSerial = issuingCert ==null? null: new IssuerSerial(GeneralNames.getInstance(issuingCert.getIssuerX500Principal().getEncoded()), issuingCert.getSerialNumber());

 		AttributeTable signedAttributes = CMSUtils.getSignedAttributes(cadesSignature.getSignerInformation());
		Attribute attribute = signedAttributes.get(PKCSObjectIdentifiers.id_aa_signingCertificate);
 		if (attribute != null) {
 			final byte[] signerCertHash = cadesSignature.getSigningCertificateToken().getDigest(DigestAlgorithm.SHA1);
 			final byte[] issuingCertHash = cadesSignature.getSigningCertificateToken().getDigest(DigestAlgorithm.SHA1);
 			for(ASN1Encodable enc : attribute.getAttrValues()) {
 				SigningCertificate signingCertificate = SigningCertificate.getInstance(enc);
 				for (ESSCertID certId : signingCertificate.getCerts()) {
 					if (equalsCertificateReference(certId, signerCertIssuerSerial, signerCertHash)) {
 						foundSignerCert = true;
 					} else {
 						if (mandatedCertificateRef == CertRefReq.signerOnly) {
 							errors.put("signerRules.mandatedCertificateRef", "Found more certificate references than expected");
 							return;
 						}
 						if (equalsCertificateReference(certId, issuingCertIssuerSerial, issuingCertHash)) {
 							foundIssuingCert = true;
 						}
 					}
 				}
 			}
 		}
 		
 		attribute = signedAttributes.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
 		if (attribute != null) {
 			for(ASN1Encodable enc : attribute.getAttrValues()) {
 				SigningCertificateV2 signingCertificateV2 = SigningCertificateV2.getInstance(enc);
 				for (ESSCertIDv2 certId : signingCertificateV2.getCerts()) {
 					if (equalsCertificateReference(certId, signerCertIssuerSerial, cadesSignature.getSigningCertificateToken())) {
 						foundSignerCert = true;
 					} else {
 						if (mandatedCertificateRef == CertRefReq.signerOnly) {
 							errors.put("signerRules.mandatedCertificateRef", "Found more certificate references than expected");
 							return;
 						}
 						if (equalsCertificateReference(certId, issuingCertIssuerSerial, cadesSignature.getSigningCertificateToken().getIssuerToken())) {
 							foundIssuingCert = true;
 						}
 					}
 				}
 			}
 		}
		
		if (!foundSignerCert) {
			errors.put("signerRules.mandatedCertificateRef", "No signing certificate reference found");
			return;
		}
		
		if (mandatedCertificateRef == CertRefReq.fullPath && !foundIssuingCert) {
			errors.put("signerRules.mandatedCertificateRef", "Found less references than expected");
		}
			
	}
	
	private boolean equalsCertificateReference(ESSCertID certId, IssuerSerial certIssuerSerial, byte[] certHash) {
		if (certId.getIssuerSerial().equals(certIssuerSerial)) {
			if (!Arrays.areEqual(certHash, certId.getCertHash())) {
				return true;
			}
		}
		return false;
	}
	
	private boolean equalsCertificateReference(ESSCertIDv2 certId, IssuerSerial certIssuerSerial, CertificateToken tk) {
		if (tk == null) {
			return false;
		}
		
		final byte[] certHash = tk.getDigest(DigestAlgorithm.forOID(certId.getHashAlgorithm().getAlgorithm().getId()));
		if (certId.getIssuerSerial().equals(certIssuerSerial)) {
			if (!Arrays.areEqual(certHash, certId.getCertHash())) {
				return true;
			}
		}
		return false;
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
			} else if (mandatedCertificateInfo == CertInfoReq.fullPath && !containsSignerFullChain(cadesSignature.getCertificateSource().getKeyInfoCertificates())) {
				errors.put("signerRules.mandatedCertificateInfo", "Should have the signer certificate full path in the signature");
			}
		}
	}

	private boolean containsSignerFullChain(List<CertificateToken> certificates) {
		if (signerCertPath.isEmpty() || (signerCertPath.size() == 1 && signerCertPath.contains(cadesSignature.getSigningCertificateToken()))) {
			// If it was not possible to build the certification path, any check should fail
			return false;
		}
		
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
