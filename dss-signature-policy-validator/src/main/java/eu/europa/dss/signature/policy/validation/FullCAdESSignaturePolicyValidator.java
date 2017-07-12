package eu.europa.dss.signature.policy.validation;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
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
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.dss.signature.policy.CertInfoReq;
import eu.europa.dss.signature.policy.CertRefReq;
import eu.europa.dss.signature.policy.CertificateTrustPoint;
import eu.europa.dss.signature.policy.CertificateTrustTrees;
import eu.europa.dss.signature.policy.CommitmentRule;
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

/**
 * SignaturePolicy validation consists in matching the commitment rules with the given CMS blob
 * @author davyd.santos
 *
 */
public class FullCAdESSignaturePolicyValidator extends BasicCAdESSignaturePolicyValidator {

	private static final Logger LOG = LoggerFactory.getLogger(FullCAdESSignaturePolicyValidator.class);

	private Map<String, String> errors = new HashMap<String, String>();
	
	private List<CertificateToken> signerCertPath = null;

	public FullCAdESSignaturePolicyValidator(SignaturePolicyProvider signaturePolicyProvider, CAdESSignature sig) {
		super(signaturePolicyProvider, sig);
	}

	@Override
	public Map<String, String> validate() {
		//  Upper class initializes the signature policy and validates the hash of the policy in 
		// the declared attribute and the value in the policy itself
		errors.putAll(super.validate());
		
		// TODO IMPLICIT POLICY
		// TODO Skip non processable ASN1
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
		Set<CommitmentRule> cmmtRules = findCommitmentRule(cadesSignature.getCommitmentTypeIndication() == null? null: cadesSignature.getCommitmentTypeIndication().getIdentifiers());
		
		//TODO do I have to validate all or if one matches is enough?
		for (CommitmentRule cmmtRule : cmmtRules) {
			validateSigningCertTrustContition(cmmtRule.getSigningCertTrustCondition());
			// TimestampTrustCondition 
			// AttributeTrustCondition
			// AlgorithmConstraintSet
			validateSignerAndVeriferRules(cmmtRule.getSignerAndVeriferRules());
		}
	}

	private void validateSigningCertTrustContition(SigningCertTrustCondition signingCertTrustCondition) {
		RevReqValidator revReqValidator = new RevReqValidator(signingCertTrustCondition.getSignerRevReq().getEndCertRevReq(), cadesSignature.getSigningCertificateToken());
		if (!revReqValidator.validate()) {
			errors.put("signingCertTrustCondition.signerRevReq.endCertRevReq", "End certificate is revoked");
		}
		try {
			signerCertPath = validateCertTrustContition("signingCertTrustCondition", cadesSignature.getSigningCertificateToken(), signingCertTrustCondition.getSignerTrustTrees());

			for (CertificateToken certificate : signerCertPath) {
				revReqValidator = new RevReqValidator(signingCertTrustCondition.getSignerRevReq().getCaCerts(), certificate);
				if (!revReqValidator.validate()) {
					errors.put("signingCertTrustCondition.signerRevReq.endCertRevReq", "One of the CA certificates is revoked");
					break;
				}
			}
		} catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | IOException e) {
			errors.put("signingCertTrustCondition", "unexpected error");
			LOG.warn("Error on validating signingCertTrustCondition", e);
		}
	}

	protected List<CertificateToken> validateCertTrustContition(String label, CertificateToken certificate, CertificateTrustTrees certificateTrustTrees) throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		if (certificateTrustTrees == null || certificateTrustTrees.getCertificateTrustPoints().isEmpty()) {
			return CertificateTrustPointValidator.buildKnownChain(certificate);
		}
		
		CertStore certStore = CertificateTrustPointValidator.buildCertStore(certificate);
		for (CertificateTrustPoint trustPoint : certificateTrustTrees.getCertificateTrustPoints()) {
			CertificateTrustPointValidator trustPointValidator = new CertificateTrustPointValidator(cadesSignature.getCertPool(), certStore, trustPoint);
			if (trustPointValidator.validate()) {
				return trustPointValidator.getChainCertificates();
			}
		}
		return Collections.emptyList();
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
		
		for (CertificateToken cert : signerCertPath) {
			if (!certificates.contains(cert)) {
				return false;
			}
		}
		
		return true;
	}

	public Set<CommitmentRule> findCommitmentRule(List<String> identifiers) {
		Set<CommitmentRule> commtRules = new LinkedHashSet<CommitmentRule>();
		SignatureValidationPolicy signatureValidationPolicy = getSignatureValidationPolicy();
		for (CommitmentRule cmmtRule : signatureValidationPolicy.getCommitmentRules()) {
			if (identifiers == null || identifiers.isEmpty()) {
				if (cmmtRule.getSelCommitmentTypes().contains(null)) {
					commtRules.add(new CommitmentRuleWrapper(cmmtRule, signatureValidationPolicy.getCommonRules()));
				}
			} else {
				for (String oid : identifiers) {
					if (cmmtRule.getSelCommitmentTypes().contains(oid)) {
						commtRules.add(new CommitmentRuleWrapper(cmmtRule, signatureValidationPolicy.getCommonRules())); 
					}
				}
			}
		}
		
		if (commtRules.isEmpty()) {
			// RFC 3125
			// "... the electronic signature must contain a commitment type indication
			// that must fit one of the commitments types that are mentioned in
			// CommitmentType."
			throw new DSSException("The commitment type used was not found");
		}
		return commtRules;
	}

	public SignatureValidationPolicy getSignatureValidationPolicy() {
		SignaturePolicy policy = parse();
		SignatureValidationPolicy signatureValidationPolicy = policy.getSignPolicyInfo().getSignatureValidationPolicy();
		return signatureValidationPolicy;
	}
	
}
