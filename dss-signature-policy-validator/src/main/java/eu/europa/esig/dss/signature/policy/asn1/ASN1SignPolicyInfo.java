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
package eu.europa.esig.dss.signature.policy.asn1;

import java.text.ParseException;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x509.GeneralNames;

import eu.europa.esig.dss.signature.policy.SignPolExtn;
import eu.europa.esig.dss.signature.policy.SignPolicyInfo;
import eu.europa.esig.dss.signature.policy.SignatureValidationPolicy;

/**
 * SignPolicyInfo ::= SEQUENCE {
 *  signPolicyIdentifier SignPolicyId,
 *  dateOfIssue GeneralizedTime,
 *  policyIssuerName PolicyIssuerName,
 *  fieldOfApplication FieldOfApplication,
 *  signatureValidationPolicy SignatureValidationPolicy,
 *  signPolExtensions SignPolExtensions OPTIONAL }
 * 
 * @author davyd.santos
 *
 */
public class ASN1SignPolicyInfo extends ASN1Object implements SignPolicyInfo {
	
	 private String signPolicyIdentifier;
	 private Date dateOfIssue;
	 private GeneralNames policyIssuerName;
	 private DirectoryString fieldOfApplication;
	 private ASN1SignatureValidationPolicy signatureValidationPolicy;
	 private ASN1SignPolExtensions signPolExtensions;

	public static ASN1SignPolicyInfo getInstance(ASN1Encodable obj) {
		if (obj instanceof ASN1Sequence) {
			return new ASN1SignPolicyInfo((ASN1Sequence) obj);
		}
        else if (obj != null)
        {
            return new ASN1SignPolicyInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
	}
	
	public ASN1SignPolicyInfo(ASN1Sequence as) {
		if (!(as.size() == 5 || as.size() == 6)) {
            throw new IllegalArgumentException("Bad sequence size: " + as.size());
		}
		signPolicyIdentifier = ASN1ObjectIdentifier.getInstance(as.getObjectAt(0)).getId();
		try {
			dateOfIssue = ASN1GeneralizedTime.getInstance(as.getObjectAt(1)).getDate();
		} catch (ParseException e) {
			throw new IllegalArgumentException("Error parsing SignaturePolicyInfo.dateofIssue", e);
		}
		policyIssuerName = GeneralNames.getInstance(as.getObjectAt(2));
		fieldOfApplication = DirectoryString.getInstance(as.getObjectAt(3));
		signatureValidationPolicy = ASN1SignatureValidationPolicy.getInstance(as.getObjectAt(4));
		
		if (as.size() == 6) {
			signPolExtensions = ASN1SignPolExtensions.getInstance(as.getObjectAt(5));
		}
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector entries = new ASN1EncodableVector();
		entries.add(new ASN1ObjectIdentifier(signPolicyIdentifier));
		entries.add(new ASN1GeneralizedTime(dateOfIssue));
		entries.add(policyIssuerName);
		entries.add(fieldOfApplication);
		entries.add(signatureValidationPolicy);
		if (signPolExtensions != null) {
			entries.add(signPolExtensions);			
		}
		return new DERSequence(entries);
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignPolicyInfo#getSignPolicyIdentifier()
	 */
	@Override
	public String getSignPolicyIdentifier() {
		return signPolicyIdentifier;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignPolicyInfo#getDateOfIssue()
	 */
	@Override
	public Date getDateOfIssue() {
		return dateOfIssue;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignPolicyInfo#getPolicyIssuerName()
	 */
	@Override
	public GeneralNames getPolicyIssuerName() {
		return policyIssuerName;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignPolicyInfo#getFieldOfApplication()
	 */
	@Override
	public String getFieldOfApplication() {
		return fieldOfApplication.getString();
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignPolicyInfo#getSignatureValidationPolicy()
	 */
	@Override
	public SignatureValidationPolicy getSignatureValidationPolicy() {
		return signatureValidationPolicy;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.SignPolicyInfo#getSignPolExtensions()
	 */
	@Override
	public List<SignPolExtn> getSignPolExtensions() {
		return signPolExtensions == null? null: signPolExtensions.getSignPolExtensions();
	}

}
