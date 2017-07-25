package eu.europa.esig.dss.signature.policy.asn1;

import static eu.europa.esig.dss.signature.policy.asn1.ASN1Utils.createASN1Sequence;
import static eu.europa.esig.dss.signature.policy.asn1.ASN1Utils.tag;

import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

import eu.europa.esig.dss.signature.policy.AlgorithmConstraintSet;
import eu.europa.esig.dss.signature.policy.AttributeTrustCondition;
import eu.europa.esig.dss.signature.policy.CommonRules;
import eu.europa.esig.dss.signature.policy.SignPolExtn;
import eu.europa.esig.dss.signature.policy.SignerAndVerifierRules;
import eu.europa.esig.dss.signature.policy.SigningCertTrustCondition;
import eu.europa.esig.dss.signature.policy.TimestampTrustCondition;

/**
 * CommonRules ::= SEQUENCE {
 *  signerAndVeriferRules [0] SignerAndVerifierRules OPTIONAL,
 *  signingCertTrustCondition [1] SigningCertTrustCondition OPTIONAL, 
 *  timeStampTrustCondition [2] TimestampTrustCondition OPTIONAL,
 *  attributeTrustCondition [3] AttributeTrustCondition OPTIONAL,
 *  algorithmConstraintSet [4] AlgorithmConstraintSet OPTIONAL,
 *  signPolExtensions [5] SignPolExtensions OPTIONAL
 *  } 
 * @author davyd.santos
 *
 */
public class ASN1CommonRules extends ASN1Object implements CommonRules {
	private ASN1SignerAndVeriferRules signerAndVeriferRules;
	private ASN1SigningCertTrustCondition signingCertTrustCondition;
	private ASN1TimestampTrustCondition timeStampTrustCondition;
	private ASN1AttributeTrustCondition attributeTrustCondition;
	private ASN1AlgorithmConstraintSet algorithmConstraintSet;
	private ASN1SignPolExtensions signPolExtensions;

	public static ASN1CommonRules getInstance(ASN1Encodable obj) {
		if (obj != null) {
            return new ASN1CommonRules(ASN1Sequence.getInstance(obj));
        }
		
		return null;
	}

	public ASN1CommonRules(ASN1Sequence as) {
		int index = 0;
		ASN1TaggedObject asn1TaggedObject = as.size() > index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		if (asn1TaggedObject != null && asn1TaggedObject.getTagNo() == 0) {
			signerAndVeriferRules = ASN1SignerAndVeriferRules.getInstance(asn1TaggedObject.getObject());
		
			asn1TaggedObject = as.size() > index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		}
		if (asn1TaggedObject != null && asn1TaggedObject.getTagNo() == 1) {
			signingCertTrustCondition = ASN1SigningCertTrustCondition.getInstance(asn1TaggedObject.getObject());
		
			asn1TaggedObject = as.size() > index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		}
		if (asn1TaggedObject != null && asn1TaggedObject.getTagNo() == 2) {
			timeStampTrustCondition = ASN1TimestampTrustCondition.getInstance(asn1TaggedObject.getObject());
		
			asn1TaggedObject = as.size() > index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		}
		if (asn1TaggedObject != null && asn1TaggedObject.getTagNo() == 3) {
			attributeTrustCondition = ASN1AttributeTrustCondition.getInstance(asn1TaggedObject.getObject());
		
			asn1TaggedObject = as.size() > index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		}
		if (asn1TaggedObject != null && asn1TaggedObject.getTagNo() == 4) {
			algorithmConstraintSet = ASN1AlgorithmConstraintSet.getInstance(asn1TaggedObject.getObject());
		
			asn1TaggedObject = as.size() > index? ASN1TaggedObject.getInstance(as.getObjectAt(index++)): null;
		}
		if (asn1TaggedObject != null && asn1TaggedObject.getTagNo() == 5) {
			signPolExtensions = ASN1SignPolExtensions.getInstance(asn1TaggedObject.getObject());
			
			index++;
		}
		if (as.size() > index) {
			throw new IllegalArgumentException("Unkown content found");
		}
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return createASN1Sequence(
				tag(0, signerAndVeriferRules),
				tag(1, signingCertTrustCondition),
				tag(2, timeStampTrustCondition),
				tag(3, attributeTrustCondition),
				tag(4, algorithmConstraintSet),
				tag(5, signPolExtensions));
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CommonRules#getSignerAndVeriferRules()
	 */
	@Override
	public SignerAndVerifierRules getSignerAndVeriferRules() {
		return signerAndVeriferRules;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CommonRules#getSigningCertTrustCondition()
	 */
	@Override
	public SigningCertTrustCondition getSigningCertTrustCondition() {
		return signingCertTrustCondition;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CommonRules#getTimeStampTrustCondition()
	 */
	@Override
	public TimestampTrustCondition getTimeStampTrustCondition() {
		return timeStampTrustCondition;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CommonRules#getAttributeTrustCondition()
	 */
	@Override
	public AttributeTrustCondition getAttributeTrustCondition() {
		return attributeTrustCondition;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CommonRules#getAlgorithmConstraintSet()
	 */
	@Override
	public AlgorithmConstraintSet getAlgorithmConstraintSet() {
		return algorithmConstraintSet;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CommonRules#getSignPolExtensions()
	 */
	@Override
	public List<SignPolExtn> getSignPolExtensions() {
		return signPolExtensions.getSignPolExtn();
	}

}
