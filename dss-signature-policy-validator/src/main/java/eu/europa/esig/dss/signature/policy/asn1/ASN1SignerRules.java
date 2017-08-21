package eu.europa.esig.dss.signature.policy.asn1;

import static eu.europa.esig.dss.signature.policy.asn1.ASN1Utils.createASN1Sequence;
import static eu.europa.esig.dss.signature.policy.asn1.ASN1Utils.getTagEnumeratedValue;
import static eu.europa.esig.dss.signature.policy.asn1.ASN1Utils.tag;

import java.util.List;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

import eu.europa.esig.dss.signature.policy.CertInfoReq;
import eu.europa.esig.dss.signature.policy.CertRefReq;
import eu.europa.esig.dss.signature.policy.SignPolExtn;
import eu.europa.esig.dss.signature.policy.SignerRules;

/**
 * SignerRules ::= SEQUENCE {
 *  externalSignedData BOOLEAN OPTIONAL,
 *   -- True if signed data is external to CMS structure
 *   -- False if signed data part of CMS structure
 *   -- not present if either allowed
 *  mandatedSignedAttr CMSAttrs, -- Mandated CMS signed attributes
 *  mandatedUnsignedAttr CMSAttrs, -- Mandated CMS unsigned attributed
 *  mandatedCertificateRef [0] CertRefReq DEFAULT signerOnly,
 *   -- Mandated Certificate Reference
 *  mandatedCertificateInfo [1] CertInfoReq DEFAULT none,
 *   -- Mandated Certificate Info
 *  signPolExtensions [2] SignPolExtensions OPTIONAL
 *  } 
 * @author davyd.santos
 *
 */
public class ASN1SignerRules extends ASN1Object implements SignerRules {
	private Boolean externalSignedData;
	private ASN1CMSAttrs mandatedSignedAttr;
	private ASN1CMSAttrs mandatedUnsignedAttr;
	private CertRefReq mandatedCertificateRef;
	private CertInfoReq mandatedCertificateInfo;
	private ASN1SignPolExtensions signPolExtensions;

	public static ASN1SignerRules getInstance(ASN1Encodable obj) {
		if (obj != null) {
            return new ASN1SignerRules(ASN1Sequence.getInstance(obj));
        }
		return null;
	}

	public ASN1SignerRules(ASN1Sequence as) {
		int index = 0;
		ASN1Encodable asn = as.getObjectAt(index++);
		if (as.size() < 4 || as.size() > 6) {
            throw new IllegalArgumentException("Bad sequence size: " + as.size());
		}
		if (asn instanceof ASN1Boolean) {
			externalSignedData = ((ASN1Boolean) asn).isTrue();
			asn = as.getObjectAt(index++);
		}
		mandatedSignedAttr = ASN1CMSAttrs.getInstance(asn);
		mandatedUnsignedAttr = ASN1CMSAttrs.getInstance(as.getObjectAt(index++));
		asn = as.size() > index? as.getObjectAt(index++): null;
		Integer tagEnumeratedValue = getTagEnumeratedValue(asn, 0);
		mandatedCertificateRef = tagEnumeratedValue != null? ASN1CertRefReqHelper.getInstance(tagEnumeratedValue, null): null;
		if (tagEnumeratedValue != null) {
			asn = as.size() > index? as.getObjectAt(index++): null;
		}
		tagEnumeratedValue = getTagEnumeratedValue(asn, 1);
		mandatedCertificateInfo = tagEnumeratedValue != null? ASN1CertInfoReqHelper.getInstance(tagEnumeratedValue, null): null;
		ASN1TaggedObject taggedObj = null;
		if (tagEnumeratedValue != null && as.size() > index) {
			asn = as.size() > index? as.getObjectAt(index++): null;
		}
		taggedObj = ASN1TaggedObject.getInstance(asn);
		if (taggedObj != null) {
			signPolExtensions = ASN1SignPolExtensions.getInstance(taggedObj.getObject());
		}
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return createASN1Sequence(externalSignedData == null? null: ASN1Boolean.getInstance(externalSignedData.booleanValue()), 
				mandatedSignedAttr, 
				mandatedUnsignedAttr,
				tag(0, mandatedCertificateRef == null? null: new ASN1Enumerated(mandatedCertificateRef.ordinal())),
				tag(1, mandatedCertificateInfo == null? null: new ASN1Enumerated(mandatedCertificateInfo.ordinal())),
				tag(2, signPolExtensions));
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignerRules#getExternalSignedData()
	 */
	@Override
	public Boolean getExternalSignedData() {
		return externalSignedData;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignerRules#getMandatedSignedAttr()
	 */
	@Override
	public List<String> getMandatedSignedAttr() {
		return mandatedSignedAttr.getOids();
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignerRules#getMandatedUnsignedAttr()
	 */
	@Override
	public List<String> getMandatedUnsignedAttr() {
		return mandatedUnsignedAttr.getOids();
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignerRules#getMandatedCertificateRef()
	 */
	@Override
	public CertRefReq getMandatedCertificateRef() {
		return mandatedCertificateRef == null? null: CertRefReq.signerOnly;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignerRules#getMandatedCertificateInfo()
	 */
	@Override
	public CertInfoReq getMandatedCertificateInfo() {
		return mandatedCertificateInfo == null? null: CertInfoReq.none;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignerRules#getSignPolExtensions()
	 */
	@Override
	public List<SignPolExtn> getSignPolExtensions() {
		return signPolExtensions == null? null: signPolExtensions.getSignPolExtensions();
	}

}
