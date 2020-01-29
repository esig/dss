/**
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
 */
package eu.europa.esig.dss.validation;

import static eu.europa.esig.dss.spi.OID.attributeCertificateRefsOid;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certificateRefs;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificatePool;

@SuppressWarnings("serial")
public abstract class CMSCertificateSource extends SignatureCertificateSource {

	private static final Logger LOG = LoggerFactory.getLogger(CMSCertificateSource.class);

	protected final transient AttributeTable unsignedAttributes;

	protected CMSCertificateSource(final AttributeTable unsignedAttributes, CertificatePool certPool) {
		super(certPool);
		this.unsignedAttributes = unsignedAttributes;
	}

	@Override
	public List<CertificateToken> getCertificateValues() {
		return getCertificateFromUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_certValues);
	}

	@Override
	public List<CertificateRef> getCompleteCertificateRefs() {
		return getCertificateRefsFromUnsignedAttribute(id_aa_ets_certificateRefs, CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS);
	}

	@Override
	public List<CertificateRef> getAttributeCertificateRefs() {
		return getCertificateRefsFromUnsignedAttribute(attributeCertificateRefsOid, CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS);
	}

	private List<CertificateToken> getCertificateFromUnsignedAttribute(ASN1ObjectIdentifier attributeOid) {
		final List<CertificateToken> certs = new ArrayList<>();
		if (unsignedAttributes != null) {
			Attribute attribute = unsignedAttributes.get(attributeOid);
			if (attribute != null) {
				final ASN1Sequence seq = (ASN1Sequence) attribute.getAttrValues().getObjectAt(0);
				for (int ii = 0; ii < seq.size(); ii++) {
					try {
						final Certificate cs = Certificate.getInstance(seq.getObjectAt(ii));
						final CertificateToken certToken = addCertificate(DSSUtils.loadCertificate(cs.getEncoded()));
						if (!certs.contains(certToken)) {
							certs.add(certToken);
						}
					} catch (Exception e) {
						LOG.warn("Unable to parse encapsulated certificate : {}", e.getMessage());
					}
				}
			}
		}
		return certs;
	}

	private List<CertificateRef> getCertificateRefsFromUnsignedAttribute(ASN1ObjectIdentifier attributeOid, CertificateRefOrigin location) {
		List<CertificateRef> result = new ArrayList<>();
		if (unsignedAttributes != null) {
			Attribute attribute = unsignedAttributes.get(attributeOid);
			if (attribute != null) {
				final ASN1Sequence seq = (ASN1Sequence) attribute.getAttrValues().getObjectAt(0);
				for (int ii = 0; ii < seq.size(); ii++) {
					try {
						OtherCertID otherCertId = OtherCertID.getInstance(seq.getObjectAt(ii));
						DigestAlgorithm digestAlgo = DigestAlgorithm.forOID(otherCertId.getAlgorithmHash().getAlgorithm().getId());
						CertificateRef certRef = new CertificateRef();
						certRef.setCertDigest(new Digest(digestAlgo, otherCertId.getCertHash()));
						IssuerSerial issuerSerial = otherCertId.getIssuerSerial();
						if (issuerSerial != null) {
							certRef.setIssuerInfo(getIssuerInfo(issuerSerial));
						}
						certRef.setOrigin(location);
						result.add(certRef);
					} catch (Exception e) {
						LOG.warn("Unable to parse encapsulated OtherCertID : {}", e.getMessage());
					}
				}
			}
		}
		return result;
	}

}
