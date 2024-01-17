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
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.esf.CrlListID;
import org.bouncycastle.asn1.esf.CrlOcspRef;
import org.bouncycastle.asn1.esf.CrlValidatedID;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;

import static eu.europa.esig.dss.spi.OID.attributeRevocationRefsOid;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_revocationRefs;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_revocationValues;

/**
 * CRLSource that retrieves information from a {@link CMSSignedData} container.
 *
 */
@SuppressWarnings("serial")
public abstract class CMSCRLSource extends OfflineCRLSource {

	private static final Logger LOG = LoggerFactory.getLogger(CMSCRLSource.class);

	/** The CMS SignedData */
	private final transient CMSSignedData cmsSignedData;

	/** Represents unsigned properties */
	private final transient AttributeTable unsignedAttributes;

	/**
	 * The default constructor for CMSCRLSource.
	 *
	 * @param cmsSignedData      {@link CMSSignedData}
	 * @param unsignedAttributes {@link AttributeTable} unsignedAttributes
	 */
	protected CMSCRLSource(final CMSSignedData cmsSignedData, final AttributeTable unsignedAttributes) {
		this.cmsSignedData = cmsSignedData;
		this.unsignedAttributes = unsignedAttributes;
		extract();
	}

	private void extract() {

		// Adds CRLs contained in SignedData
		collectFromSignedData();

		if (unsignedAttributes != null) {

			/*
			 * ETSI TS 101 733 V2.2.1 (2013-04) page 43 6.3.4 revocation-values Attribute
			 * Definition This attribute is used to contain the revocation information
			 * required for the following forms of extended electronic signature: CAdES-X
			 * Long, ES X-Long Type 1, and CAdES-X Long Type 2, see clause B.1.1 for an
			 * illustration of this form of electronic signature. The revocation-values
			 * attribute is an unsigned attribute. Only a single instance of this attribute
			 * shall occur with an electronic signature. It holds the values of CRLs and
			 * OCSP referenced in the complete-revocation-references attribute.
			 * 
			 * RevocationValues ::= SEQUENCE { crlVals [0] SEQUENCE OF CertificateList
			 * OPTIONAL, ocspVals [1] SEQUENCE OF BasicOCSPResponse OPTIONAL, otherRevVals
			 * [2] OtherRevVals OPTIONAL}
			 */
			collectRevocationValues(unsignedAttributes, id_aa_ets_revocationValues, RevocationOrigin.REVOCATION_VALUES);

			/*
			 * ETSI TS 101 733 V2.2.1 (2013-04) pages 39,41 6.2.2
			 * complete-revocation-references Attribute Definition and 6.2.4
			 * attribute-revocation-references Attribute Definition The
			 * complete-revocation-references attribute is an unsigned attribute. Only a
			 * single instance of this attribute shall occur with an electronic signature.
			 * It references the full set of the CRL, ACRL, or OCSP responses that have been
			 * used in the validation of the signer, and CA certificates used in ES with
			 * Complete validation data. The complete-revocation-references attribute value
			 * has the ASN.1 syntax CompleteRevocationRefs
			 * 
			 * CompleteRevocationRefs ::= SEQUENCE OF CrlOcspRef CrlOcspRef ::= SEQUENCE {
			 * crlids [0] CRLListID OPTIONAL, ocspids [1] OcspListID OPTIONAL, otherRev [2]
			 * OtherRevRefs OPTIONAL } AttributeRevocationRefs ::= SEQUENCE OF CrlOcspRef
			 * (the same as for CompleteRevocationRefs)
			 */
			collectRevocationRefs(id_aa_ets_revocationRefs, RevocationRefOrigin.COMPLETE_REVOCATION_REFS);

			/*
			 * id-aa-ets-attrRevocationRefs OBJECT IDENTIFIER ::= { iso(1) member-body(2)
			 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 45}
			 */
			collectRevocationRefs(attributeRevocationRefsOid, RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS);

		}

	}

	private void collectFromSignedData() {
		final Store<X509CRLHolder> crLs = cmsSignedData.getCRLs();
		final Collection<X509CRLHolder> collection = crLs.getMatches(null);
		for (final X509CRLHolder x509CRLHolder : collection) {
			addX509CRLHolder(x509CRLHolder, RevocationOrigin.CMS_SIGNED_DATA);
		}
	}

	private void collectRevocationValues(AttributeTable attributeTable, ASN1ObjectIdentifier revocationValuesAttribute,
										 RevocationOrigin origin) {
		Attribute[] attributes = DSSASN1Utils.getAsn1Attributes(attributeTable, revocationValuesAttribute);
		for (Attribute attribute : attributes) {
			ASN1Encodable[] attributeValues = attribute.getAttributeValues();
			if (Utils.isArrayNotEmpty(attributeValues)) {
				for (ASN1Encodable attrValue : attributeValues) {
					extractRevocationValues(attrValue, origin);
				}
			}
		}
	}

	private void extractRevocationValues(ASN1Encodable attrValue, RevocationOrigin origin) {
		RevocationValues revValues = DSSASN1Utils.getRevocationValues(attrValue);
		if (revValues != null) {
			for (final CertificateList revValue : revValues.getCrlVals()) {
				try {
					addX509CRLHolder(new X509CRLHolder(revValue), origin);
				} catch (Exception e) {
					String errorMessage = "Unable to process CRL binary : {}";
					if (LOG.isDebugEnabled()) {
						LOG.warn(errorMessage, e.getMessage(), e);
					} else {
						LOG.warn(errorMessage, e.getMessage());
					}
				}
			}
		}
	}

	/**
	 * Computes and store {@code CRLBinary} from {@code crlHolder}
	 * 
	 * @param crlHolder {@link X509CRLHolder} to compute values from
	 * @param origin    {@link RevocationOrigin} indicating the list where to save
	 *                  the object
	 */
	protected void addX509CRLHolder(X509CRLHolder crlHolder, RevocationOrigin origin) {
		try {
			addBinary(CRLUtils.buildCRLBinary(crlHolder.getEncoded()), origin);
		} catch (Exception e) {
			throw new DSSException(String.format("Unable to parse CRL binaries from origin '%s'. Reason : %s",
					origin, e.getMessage()), e);
		}
	}

	private void collectRevocationRefs(ASN1ObjectIdentifier revocationRefsAttribute, RevocationRefOrigin origin) {
		try {
			Attribute[] attributes = DSSASN1Utils.getAsn1Attributes(unsignedAttributes, revocationRefsAttribute);
			for (Attribute attribute : attributes) {
				ASN1Encodable[] attributeValues = attribute.getAttributeValues();
				if (Utils.isArrayNotEmpty(attributeValues)) {
					for (ASN1Encodable attrValue : attributeValues) {
						final ASN1Sequence revocationRefs = (ASN1Sequence) attrValue;
						for (int ii = 0; ii < revocationRefs.size(); ii++) {
							collectRevocationRefFromASN1Encodable(revocationRefs.getObjectAt(ii), origin);
						}
					}
				}
			}
		} catch (Exception e) {
			// When error in computing or in format, the algorithm just continues.
			LOG.warn(
					"An error occurred during extraction of revocation references from  signature unsigned properties. "
							+ "Revocations for origin {} were not stored",
					origin.toString(), e);
		}
	}

	private void collectRevocationRefFromASN1Encodable(ASN1Encodable asn1Encodable, RevocationRefOrigin origin) {
		try {
			final CrlOcspRef crlOcspRef = CrlOcspRef.getInstance(asn1Encodable);
			final CrlListID crlIds = crlOcspRef.getCrlids();
			if (crlIds != null) {
				for (final CrlValidatedID id : crlIds.getCrls()) {
					final CRLRef crlRef = new CRLRef(id);
					addRevocationReference(crlRef, origin);
				}
			}
		} catch (Exception e) {
			String errorMessage = "Unable to process CRL reference : {}";
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, e.getMessage(), e);
			} else {
				LOG.warn(errorMessage, e.getMessage());
			}
		}
	}

}
