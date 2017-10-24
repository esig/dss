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
import static eu.europa.esig.dss.signature.policy.asn1.ASN1Utils.integer;
import static eu.europa.esig.dss.signature.policy.asn1.ASN1Utils.tag;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedHashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.NameConstraints;

import eu.europa.esig.dss.signature.policy.CertificateTrustPoint;
import eu.europa.esig.dss.signature.policy.PolicyConstraints;

/**
 * CertificateTrustPoint ::= SEQUENCE {
 *         trustpoint                              Certificate,
 *                                -- self-signed certificate
 *         pathLenConstraint       [0] PathLenConstraint   OPTIONAL,
 *         acceptablePolicySet     [1] AcceptablePolicySet OPTIONAL,
 *                                 -- If not present "any policy"
 *         nameConstraints         [2] NameConstraints     OPTIONAL,
 *         policyConstraints       [3] PolicyConstraints   OPTIONAL }
 *         
 * @author davyd.santos
 *
 */
public class ASN1CertificateTrustPoint extends ASN1Object implements CertificateTrustPoint {
	private X509Certificate trustpoint;
	private Integer pathLenConstraint;
	private Set<String> acceptablePolicySet;
	private NameConstraints nameConstraints;
	private ASN1PolicyConstraints policyConstraints;
	

	public static ASN1CertificateTrustPoint getInstance(ASN1Encodable obj) {
		if (obj != null) {
			return new ASN1CertificateTrustPoint(ASN1Sequence.getInstance(obj));
		}
		return null;
	}

	public ASN1CertificateTrustPoint(ASN1Sequence as) {
		int index = 0;
		byte[] certificateEncoded;
		try {
			certificateEncoded = as.getObjectAt(index++).toASN1Primitive().getEncoded();
			trustpoint = (X509Certificate) CertificateFactory.getInstance("X.509").
					generateCertificate(new ByteArrayInputStream(certificateEncoded));
		} catch (IOException | CertificateException  e) {
			throw new IllegalArgumentException("Unexpected value found", e);
		}
		if (as.size() == index) {
			return;
		}
		
		ASN1TaggedObject to = ASN1TaggedObject.getInstance(as.getObjectAt(index++));
		if (to.getTagNo() == 0) {
			pathLenConstraint = ((ASN1Integer) to.getObject()).getValue().intValue();
			if (as.size() == index) {
				return;
			}
			to = ASN1TaggedObject.getInstance(as.getObjectAt(index++));
		}
		
		if (to.getTagNo() == 1) {
			acceptablePolicySet = new LinkedHashSet<String>();
			ASN1Sequence seqPol  = ASN1Sequence.getInstance(to.getObject());
			for (ASN1Encodable asn1Encodable : seqPol) {
				acceptablePolicySet.add(ASN1ObjectIdentifier.getInstance(asn1Encodable).getId());
			}
			if (as.size() == index) {
				return;
			}
			to = ASN1TaggedObject.getInstance(as.getObjectAt(index++));
		}
		
		if (to.getTagNo() == 2) {
			nameConstraints = NameConstraints.getInstance(to.getObject());
			if (as.size() == index) {
				return;
			}
			to = ASN1TaggedObject.getInstance(as.getObjectAt(index++));
		}
		
		if (to.getTagNo() == 3) {
			policyConstraints = ASN1PolicyConstraints.getInstance(to.getObject());
		}
		if (as.size() != index) {
			throw new IllegalArgumentException("Bad sequence content, size: " + as.size());
		}
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1Encodable cert = null;
		try (ASN1InputStream is = new ASN1InputStream(trustpoint.getEncoded())) {
			cert = is.readObject();
		} catch (CertificateEncodingException | IOException e) {
			throw new RuntimeException("Error trust point certificate", e);
		}
		
		DERSequence acceptablePolicies = null;
		if (acceptablePolicySet != null) {
			ASN1EncodableVector policies = new ASN1EncodableVector();
			for (String oid : acceptablePolicySet) {
				policies.add(new ASN1ObjectIdentifier(oid));
			}
			acceptablePolicies = new DERSequence(policies);
		}
		return createASN1Sequence(cert, 
				tag(0, integer(pathLenConstraint)),
				tag(1, acceptablePolicies),
				tag(2, nameConstraints),
				tag(3, policyConstraints));
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CertificateTrustPoint#getTrustpoint()
	 */
	@Override
	public X509Certificate getTrustpoint() {
		return trustpoint;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CertificateTrustPoint#getPathLenConstraint()
	 */
	@Override
	public Integer getPathLenConstraint() {
		return pathLenConstraint;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CertificateTrustPoint#getAcceptablePolicySet()
	 */
	@Override
	public Set<String> getAcceptablePolicySet() {
		return acceptablePolicySet;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CertificateTrustPoint#getNameConstraints()
	 */
	@Override
	public NameConstraints getNameConstraints() {
		return nameConstraints;
	}

	/* (non-Javadoc)
	 * @see docusign.signature.policy.asn1.CertificateTrustPoint#getPolicyConstraints()
	 */
	@Override
	public PolicyConstraints getPolicyConstraints() {
		return policyConstraints;
	}

}
