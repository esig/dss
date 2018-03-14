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

import static eu.europa.esig.dss.signature.policy.asn1.ASN1Utils.createASN1Sequence;
import static eu.europa.esig.dss.signature.policy.asn1.ASN1Utils.tag;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.DirectoryString;

import eu.europa.esig.dss.signature.policy.CommitmentType;

/**
 * SelectedCommitmentTypes ::= SEQUENCE OF CHOICE {
 *         empty                        NULL,
 *         recognizedCommitmentType     CommitmentType }
 *         
 * CommitmentType ::= SEQUENCE {
 *         identifier                      CommitmentTypeIdentifier,
 *         fieldOfApplication      [0] FieldOfApplication OPTIONAL,
 *         semantics               [1] DirectoryString OPTIONAL }
 *         
 * @author davyd.santos
 *
 */
public class ASN1CommitmentType extends ASN1Object implements CommitmentType {
	
	private String identifier;
	private DirectoryString fieldOfApplication;
	private DirectoryString semantics;
	
	public static ASN1CommitmentType getInstance(ASN1Encodable obj) {
		if (obj != null) {
            return new ASN1CommitmentType(ASN1Sequence.getInstance(obj));
        }

        return null;
	}

	public ASN1CommitmentType(ASN1Sequence as) {
		int index = 0;
		ASN1Encodable obj = as.getObjectAt(index++);
		identifier = ASN1ObjectIdentifier.getInstance(obj).getId();
		obj = as.size() > index? as.getObjectAt(index++): null;
		
		obj = ASN1Utils.getTagValue(obj, 0);
		if (obj != null) {
			fieldOfApplication = DirectoryString.getInstance(obj);
			obj = as.size() > index? as.getObjectAt(index++): null;
		}

		obj = ASN1Utils.getTagValue(obj, 1);
		if (obj != null) {
			fieldOfApplication = DirectoryString.getInstance(obj);
		}
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return createASN1Sequence(
				new ASN1ObjectIdentifier(identifier),
				tag(0, fieldOfApplication),
				tag(1, semantics));
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CommitmentType#getIdentifier()
	 */
	@Override
	public String getIdentifier() {
		return identifier;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CommitmentType#getFieldOfApplication()
	 */
	@Override
	public String getFieldOfApplication() {
		return fieldOfApplication.getString();
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CommitmentType#getSemantics()
	 */
	@Override
	public String getSemantics() {
		return semantics.getString();
	}

}
