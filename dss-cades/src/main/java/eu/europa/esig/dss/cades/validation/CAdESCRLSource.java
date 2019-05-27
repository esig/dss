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
package eu.europa.esig.dss.cades.validation;

import static eu.europa.esig.dss.OID.attributeRevocationRefsOid;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_revocationRefs;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_revocationValues;

import java.io.IOException;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.esf.CrlListID;
import org.bouncycastle.asn1.esf.CrlOcspRef;
import org.bouncycastle.asn1.esf.CrlValidatedID;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.x509.RevocationOrigin;
import eu.europa.esig.dss.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.x509.revocation.crl.SignatureCRLSource;

/**
 * CRLSource that retrieves information from a CAdES signature.
 *
 */
@SuppressWarnings("serial")
public class CAdESCRLSource extends SignatureCRLSource {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESCRLSource.class);

	private final CMSSignedData cmsSignedData;
	private final SignerInformation signerInformation;

	/**
	 * The default constructor for CAdESCRLSource.
	 *
	 * @param signerInformation
	 */
	public CAdESCRLSource(final CMSSignedData cmsSignedData, final SignerInformation signerInformation) {
		this.cmsSignedData = cmsSignedData;
		this.signerInformation = signerInformation;
		extract();
	}

	private void extract() {

		// Adds CRLs contained in SignedData
		final Store<X509CRLHolder> crLs = cmsSignedData.getCRLs();
		final Collection<X509CRLHolder> collection = crLs.getMatches(null);
		for (final X509CRLHolder x509CRLHolder : collection) {
			addX509CRLHolder(x509CRLHolder, RevocationOrigin.INTERNAL_REVOCATION_VALUES);
		}

		// Adds CRLs in -XL ... inside SignerInfo attribute if present
		if (signerInformation != null) {

			final AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
			if (unsignedAttributes != null) {
				/*
				 * ETSI TS 101 733 V2.2.1 (2013-04) page 43
				 * 6.3.4 revocation-values Attribute Definition
				 * This attribute is used to contain the revocation information required for the following forms of
				 * extended electronic
				 * signature: CAdES-X Long, ES X-Long Type 1, and CAdES-X Long Type 2, see clause B.1.1 for an
				 * illustration of
				 * this form of electronic signature.
				 * The revocation-values attribute is an unsigned attribute. Only a single instance of this attribute
				 * shall occur with
				 * an electronic signature. It holds the values of CRLs and OCSP referenced in the
				 * complete-revocation-references attribute.
				 * 
				 * RevocationValues ::= SEQUENCE {
				 * crlVals [0] SEQUENCE OF CertificateList OPTIONAL,
				 * ocspVals [1] SEQUENCE OF BasicOCSPResponse OPTIONAL,
				 * otherRevVals [2] OtherRevVals OPTIONAL}
				 */
				collectRevocationValues(unsignedAttributes, id_aa_ets_revocationValues, RevocationOrigin.INTERNAL_REVOCATION_VALUES);
				
				/*
				 * ETSI TS 101 733 V2.2.1 (2013-04) pages 39,41
				 * 6.2.2 complete-revocation-references Attribute Definition and
				 * 6.2.4 attribute-revocation-references Attribute Definition
				 * The complete-revocation-references attribute is an unsigned attribute. 
				 * Only a single instance of this
				 * attribute shall occur with an electronic signature. 
				 * It references the full set of the CRL, ACRL, or OCSP responses that
				 * have been used in the validation of the signer, and 
				 * CA certificates used in ES with Complete validation data.
				 * The complete-revocation-references attribute value has the ASN.1 syntax CompleteRevocationRefs
				 * 
				 * CompleteRevocationRefs ::= SEQUENCE OF CrlOcspRef
				 * CrlOcspRef ::= SEQUENCE {
				 *  crlids [0] CRLListID OPTIONAL,
				 *  ocspids [1] OcspListID OPTIONAL,
				 *  otherRev [2] OtherRevRefs OPTIONAL
				 * } 
				 * AttributeRevocationRefs ::= SEQUENCE OF CrlOcspRef (the same as for CompleteRevocationRefs)
				 */
				collectRevocationRefs(unsignedAttributes, id_aa_ets_revocationRefs, RevocationOrigin.COMPLETE_REVOCATION_REFS);
				/*
				 * id-aa-ets-attrRevocationRefs OBJECT IDENTIFIER ::= { iso(1) member-body(2)
				 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 45} 
				 */
				collectRevocationRefs(unsignedAttributes, attributeRevocationRefsOid, RevocationOrigin.ATTRIBUTE_REVOCATION_REFS);
			}

			/*
			 * TODO (pades): Read revocation data from from unsigned attribute 1.2.840.113583.1.1.8
			 * In the PKCS #7 object of a digital signature in a PDF file, identifies a signed attribute
			 * that "can include all the revocation information that is necessary to carry out revocation
			 * checks for the signer's certificate and its issuer certificates."
			 * Defined as adbe-revocationInfoArchival { adbe(1.2.840.113583) acrobat(1) security(1) 8 } in
			 * "PDF Reference, fifth edition: Adobe® Portable Document Format, Version 1.6" Adobe Systems Incorporated,
			 * 2004.
			 * http://partners.adobe.com/public/developer/en/pdf/PDFReference16.pdf page 698
			 * 
			 * RevocationInfoArchival ::= SEQUENCE {
			 * crl [0] EXPLICIT SEQUENCE of CRLs, OPTIONAL
			 * ocsp [1] EXPLICIT SEQUENCE of OCSP Responses, OPTIONAL
			 * otherRevInfo [2] EXPLICIT SEQUENCE of OtherRevInfo, OPTIONAL
			 * }
			 * OtherRevInfo ::= SEQUENCE {
			 * Type OBJECT IDENTIFIER
			 * Value OCTET STRING
			 * }
			 */

			// TODO: (Bob: 2013 Dec 03) --> NICOLAS: Is there any other container within the CAdES signature with
			// revocation data? (ie: timestamp)
		}
	}
	
	private void collectRevocationValues(AttributeTable unsignedAttributes, ASN1ObjectIdentifier revocationValuesAttribute, RevocationOrigin origin) {
		final Attribute attribute = unsignedAttributes.get(revocationValuesAttribute);
		if (attribute != null) {

			final ASN1Set attrValues = attribute.getAttrValues();

			final ASN1Encodable attValue = attrValues.getObjectAt(0);
			final RevocationValues revValues = RevocationValues.getInstance(attValue);
			for (final CertificateList revValue : revValues.getCrlVals()) {
				addX509CRLHolder(new X509CRLHolder(revValue), origin);
			}
		}
	}

	private void addX509CRLHolder(X509CRLHolder crlHolder, RevocationOrigin origin) {
		try {
			addCRLBinary(crlHolder.getEncoded(), origin);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}
	
	private void collectRevocationRefs(AttributeTable unsignedAttributes, ASN1ObjectIdentifier revocationRefsAttribute, RevocationOrigin origin) {
		try {
			final Attribute attribute = unsignedAttributes.get(revocationRefsAttribute);
			if (attribute == null) {
				return;
			}
			
			final ASN1Set attrValues = attribute.getAttrValues();
			if (attrValues.size() <= 0) {
				return;
			}
			
			final ASN1Encodable attrValue = attrValues.getObjectAt(0);
			final ASN1Sequence revocationRefs = (ASN1Sequence) attrValue;
			for (int ii = 0; ii < revocationRefs.size(); ii++) {
				final CrlOcspRef crlOcspRef = CrlOcspRef.getInstance(revocationRefs.getObjectAt(ii));
				final CrlListID crlIds = crlOcspRef.getCrlids();
				if (crlIds != null) {
					for (final CrlValidatedID id : crlIds.getCrls()) {
						final CRLRef crlRef = new CRLRef(id, origin);
						addReference(crlRef, origin);
					}
				}
			}
		} catch (Exception e) {
			// When error in computing or in format, the algorithm just continues.
			LOG.warn("An error occurred during extraction of revocation references from  signature unsigned properties. "
					+ "Revocations for origin {} were not stored", origin.toString(), e);
		}
	}

}
