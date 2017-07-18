package eu.europa.esig.dss.cades.validation;

import java.util.Collections;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import org.bouncycastle.asn1.esf.SigPolicyQualifierInfo;
import org.bouncycastle.asn1.esf.SigPolicyQualifiers;
import org.bouncycastle.asn1.esf.SignaturePolicyId;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.x509.SignaturePolicy;

/**
 * Default implementation, checks only the hash of the policy
 * @author davyd.santos
 *
 */
public class BasicCAdESSignaturePolicyValidator implements SignaturePolicyValidator {

	private static final Logger LOG = LoggerFactory.getLogger(BasicCAdESSignaturePolicyValidator.class);
	
	private SignaturePolicyProvider signaturePolicyProvider;

	private SignaturePolicy signaturePolicy;
	
	protected CAdESSignature cadesSignature;

	public BasicCAdESSignaturePolicyValidator(SignaturePolicyProvider signaturePolicyProvider, CAdESSignature sig) {
		this.signaturePolicyProvider = signaturePolicyProvider;
		this.cadesSignature = sig;
	}

	public Map<String, String> validate() {
		final Attribute attribute = CMSUtils.getSignedAttributes(cadesSignature.getSignerInformation()).get(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId);
		if (attribute == null) {
			return Collections.emptyMap();
		}

		final ASN1Encodable attrValue = attribute.getAttrValues().getObjectAt(0);
		if (attrValue instanceof DERNull) {
			return Collections.emptyMap();
		}

		final SignaturePolicyId sigPolicy = SignaturePolicyId.getInstance(attrValue);
		if (sigPolicy == null) {
			return Collections.emptyMap();
		}

		final String policyId = sigPolicy.getSigPolicyId().getId();

		signaturePolicy = new SignaturePolicy(policyId);

		final OtherHashAlgAndValue hashAlgAndValue = sigPolicy.getSigPolicyHash();

		final AlgorithmIdentifier digestAlgorithmIdentifier = hashAlgAndValue.getHashAlgorithm();
		final String digestAlgorithmOID = digestAlgorithmIdentifier.getAlgorithm().getId();
		final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(digestAlgorithmOID);
		signaturePolicy.setDigestAlgorithm(digestAlgorithm);

		final ASN1OctetString digestValue = hashAlgAndValue.getHashValue();
		final byte[] digestValueBytes = digestValue.getOctets();
		signaturePolicy.setDigestValue(Utils.toBase64(digestValueBytes));

		final SigPolicyQualifiers sigPolicyQualifiers = sigPolicy.getSigPolicyQualifiers();
		if (sigPolicyQualifiers == null) {
			signaturePolicy.setPolicyContent(signaturePolicyProvider.getSignaturePolicyById(policyId));
		} else {
			for (int ii = 0; ii < sigPolicyQualifiers.size(); ii++) {
				try {
					final SigPolicyQualifierInfo policyQualifierInfo = sigPolicyQualifiers.getInfoAt(ii);
					final ASN1ObjectIdentifier policyQualifierInfoId = policyQualifierInfo.getSigPolicyQualifierId();
					final String policyQualifierInfoValue = policyQualifierInfo.getSigQualifier().toString();

					if (PKCSObjectIdentifiers.id_spq_ets_unotice.equals(policyQualifierInfoId)) {
						signaturePolicy.setNotice(policyQualifierInfoValue);
					} else if (PKCSObjectIdentifiers.id_spq_ets_uri.equals(policyQualifierInfoId)) {
						signaturePolicy.setUrl(policyQualifierInfoValue);
						signaturePolicy.setPolicyContent(signaturePolicyProvider.getSignaturePolicyByUrl(policyQualifierInfoValue));
					} else {
						LOG.error("Unknown signature policy qualifier id: " + policyQualifierInfoId + " with value: " + policyQualifierInfoValue);
					}
				} catch (Exception e) {
					LOG.error("Unable to read SigPolicyQualifierInfo " + ii, e.getMessage());
				}
			}
		}
		
		return Collections.emptyMap();
	}
	
	public SignaturePolicy getSignaturePolicy() {
		return signaturePolicy;
	}
}
