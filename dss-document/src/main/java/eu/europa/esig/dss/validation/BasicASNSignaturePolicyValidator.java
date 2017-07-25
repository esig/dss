package eu.europa.esig.dss.validation;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.SignaturePolicy;

/**
 * Default implementation, checks only the hash of the policy
 * @author davyd.santos
 *
 */
public class BasicASNSignaturePolicyValidator implements SignaturePolicyValidator {

	private static final Logger LOG = LoggerFactory.getLogger(BasicASNSignaturePolicyValidator.class);
	
	private AdvancedSignature signature;
	private boolean identified;
	private boolean status;
	private boolean asn1Processable;
	private boolean digestAlgorithmsEqual;
	private Map<String, String> errors = new HashMap<>();

	public BasicASNSignaturePolicyValidator(AdvancedSignature sig) {
		this.signature = sig;
	}

	public void validate() {
		SignaturePolicy signaturePolicy = signature.getPolicyId();
		
		final DSSDocument policyContent = signaturePolicy.getPolicyContent();
		byte[] policyBytes = null;
		if (policyContent == null) {
			setIdentified(false);
			if (signaturePolicy.getIdentifier().isEmpty()) {
				setStatus(true);
			} else {
				setStatus(false);
			}
			return;
		} else {
			policyBytes = DSSUtils.toByteArray(policyContent);
			setStatus(true);
		}
		setIdentified(true);

		if (Utils.isArrayEmpty(policyBytes)) {
			setIdentified(false);
			errors.put("general", "Empty content for policy");
			return;
		}

		ASN1Sequence asn1Sequence = null;
		try {
			asn1Sequence = DSSASN1Utils.toASN1Primitive(policyBytes);
		} catch (Exception e) {
			LOG.info("Policy bytes are not asn1 processable : " + e.getMessage());
		}

		try {
			final String digestValue = signaturePolicy.getDigestValue();
			final DigestAlgorithm signPolicyHashAlgFromSignature = signaturePolicy.getDigestAlgorithm();
			
			if (asn1Sequence != null) {
				setAsn1Processable(true);


				/**
				 * a) If the resulting document is based on TR 102 272 [i.2] (ESI: ASN.1 format for signature policies),
				 * use the digest value present in the
				 * SignPolicyDigest element from the resulting document. Check that the digest algorithm indicated in
				 * the SignPolicyDigestAlg from the resulting
				 * document is equal to the digest algorithm indicated in the property.
				 */

				final ASN1Sequence signPolicyHashAlgObject = (ASN1Sequence) asn1Sequence.getObjectAt(0);
				final AlgorithmIdentifier signPolicyHashAlgIdentifier = AlgorithmIdentifier.getInstance(signPolicyHashAlgObject);
				DigestAlgorithm signPolicyHashAlgFromPolicy = DigestAlgorithm.forOID(signPolicyHashAlgIdentifier.getAlgorithm().getId());

				/**
				 * b) If the resulting document is based on TR 102 038 [i.3] ((ESI) XML format for signature policies),
				 * use the digest value present in
				 * signPolicyHash element from the resulting document. Check that the digest algorithm indicated in the
				 * signPolicyHashAlg from the resulting
				 * document is equal to the digest algorithm indicated in the attribute.
				 */

				/**
				 * The use of a zero-sigPolicyHash value is to ensure backwards compatibility with earlier versions of
				 * the current document. If sigPolicyHash is
				 * zero, then the hash value should not be checked against the calculated hash value of the signature
				 * policy.
				 */
				if (!signPolicyHashAlgFromPolicy.equals(signPolicyHashAlgFromSignature)) {
					addError("general", "The digest algorithm indicated in the SignPolicyHashAlg from the resulting document ("
							+ signPolicyHashAlgFromPolicy + ") is not equal to the digest " + "algorithm (" + signPolicyHashAlgFromSignature + ").");
					setDigestAlgorithmsEqual(false);
					setStatus(false);
					return;
				} else {
					setDigestAlgorithmsEqual(true);
				}

				String recalculatedDigestValue = Utils.toBase64(DSSASN1Utils.getAsn1SignaturePolicyDigest(signPolicyHashAlgFromPolicy, policyBytes));

				boolean equal = Utils.areStringsEqual(digestValue, recalculatedDigestValue);
				setStatus(equal);
				if (!equal) {
					addError("general", "The policy digest value (" + digestValue + ") does not match the re-calculated digest value (" + recalculatedDigestValue + ").");
					return;
				}

				final ASN1OctetString signPolicyHash = (ASN1OctetString) asn1Sequence.getObjectAt(2);
				final String policyDigestValueFromPolicy = Utils.toBase64(signPolicyHash.getOctets());
				equal = Utils.areStringsEqual(digestValue, policyDigestValueFromPolicy);
				setStatus(equal);
				if (!equal) {
					addError("general", "The policy digest value (" + digestValue + ") does not match the digest value from the policy file ("
							+ policyDigestValueFromPolicy + ").");
				}
			} else {
				/**
				 * c) In all other cases, compute the digest using the digesting algorithm indicated in the children of
				 * the property/attribute.
				 */
				String recalculatedDigestValue = Utils.toBase64(DSSUtils.digest(signPolicyHashAlgFromSignature, policyBytes));
				boolean equal = Utils.areStringsEqual(digestValue, recalculatedDigestValue);
				setStatus(equal);
				if (!equal) {
					addError("general", "The policy digest value (" + digestValue + ") does not match the re-calculated digest value (" + recalculatedDigestValue + ").");
				}
			}

		} catch (Exception e) {
			// When any error (communication) we just set the status to false
			setStatus(false);
			addError("general", e.getMessage());
			// Do nothing
			LOG.warn(e.getMessage(), e);
		}
	}
	
	public boolean canValidate() {
		return getSignature() != null;
	}

	public AdvancedSignature getSignature() {
		return signature;
	}

	public boolean isIdentified() {
		return identified;
	}

	public boolean isStatus() {
		return status;
	}

	public boolean isAsn1Processable() {
		return asn1Processable;
	}

	public boolean isDigestAlgorithmsEqual() {
		return digestAlgorithmsEqual;
	}

	public String getProcessingErrors() {
		StringBuilder stringBuilder = new StringBuilder();
		if (!errors.isEmpty()) {
			stringBuilder.append("The errors found on signature policy validation are:");
			for (String key : errors.keySet()) {
				stringBuilder.append(" at ").append(key).append(": ").append(errors.get(key)).append(",");
			}
			stringBuilder.setLength(stringBuilder.length()-2);
		}
		return stringBuilder.toString();
	}

	public void setSignature(AdvancedSignature signature) {
		this.signature = signature;
	}

	private void setIdentified(boolean identified) {
		this.identified = identified;
	}

	private void setStatus(boolean status) {
		this.status = status;
	}

	private void setAsn1Processable(boolean asn1Processable) {
		this.asn1Processable = asn1Processable;
	}

	private void setDigestAlgorithmsEqual(boolean digestAlgorithmsEqual) {
		this.digestAlgorithmsEqual = digestAlgorithmsEqual;
	}

	protected void addError(String key, String description) {
		this.errors.put(key, description);
	}
}