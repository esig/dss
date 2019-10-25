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

import static eu.europa.esig.dss.spi.OID.attributeRevocationRefsOid;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_revocationRefs;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_revocationValues;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
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

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;

/**
 * CRLSource that retrieves information from a {@link CMSSignedData} container.
 *
 */
@SuppressWarnings("serial")
public abstract class CMSCRLSource extends SignatureCRLSource {

	private static final Logger LOG = LoggerFactory.getLogger(CMSCRLSource.class);

	protected transient final CMSSignedData cmsSignedData;
	protected transient final AttributeTable unsignedAttributes;

	/**
	 * Cached list of {@code CRLBinary}s found in SignedData attribute
	 */
	private List<CRLBinary> signedDataCRLIdentifiers = new ArrayList<CRLBinary>();

	/**
	 * The default constructor for CMSCRLSource.
	 *
	 * @param cmsSignedData      {@link CMSSignedData}
	 * @param signerInformation {@link SignerInformation} signerInformation
	 */
	public CMSCRLSource(final CMSSignedData cmsSignedData, final AttributeTable unsignedAttributes) {
		this.cmsSignedData = cmsSignedData;
		this.unsignedAttributes = unsignedAttributes;
		extract();
	}

	/**
	 * Returns SignedData {@link RevocationOrigin}
	 * 
	 * @return {@link RevocationOrigin}
	 */
	protected RevocationOrigin getCMSSignedDataRevocationOrigin() {
		return RevocationOrigin.CMS_SIGNED_DATA;
	}

	/**
	 * Returns revocation-values {@link RevocationOrigin}
	 * 
	 * @return {@link RevocationOrigin}
	 */
	protected RevocationOrigin getRevocationValuesOrigin() {
		return RevocationOrigin.REVOCATION_VALUES;
	}

	/**
	 * Returns complete-revocation-refs {@link RevocationRefOrigin}
	 * 
	 * @return {@link RevocationRefOrigin}
	 */
	protected RevocationRefOrigin getCompleteRevocationRefsOrigin() {
		return RevocationRefOrigin.COMPLETE_REVOCATION_REFS;
	}

	/**
	 * Returns attribute-revocation-refs {@link RevocationRefOrigin}
	 * 
	 * @return {@link RevocationRefOrigin}
	 */
	protected RevocationRefOrigin getAttributeRevocationRefsOrigin() {
		return RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS;
	}

	/**
	 * Returns a list of {@code CRLBinaryIdentifier} found in the SignedData
	 * container
	 * 
	 * @return list of {@link CRLBinary}
	 */
	public List<CRLBinary> getSignedDataCRLIdentifiers() {
		return signedDataCRLIdentifiers;
	}

	protected void extract() {

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
			collectRevocationValues(unsignedAttributes, id_aa_ets_revocationValues, getRevocationValuesOrigin());

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
			collectRevocationRefs(id_aa_ets_revocationRefs, getCompleteRevocationRefsOrigin());

			/*
			 * id-aa-ets-attrRevocationRefs OBJECT IDENTIFIER ::= { iso(1) member-body(2)
			 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 45}
			 */
			collectRevocationRefs(attributeRevocationRefsOid, getAttributeRevocationRefsOrigin());

		}

	}

	protected void collectFromSignedData() {
		final Store<X509CRLHolder> crLs = cmsSignedData.getCRLs();
		final Collection<X509CRLHolder> collection = crLs.getMatches(null);
		for (final X509CRLHolder x509CRLHolder : collection) {
			signedDataCRLIdentifiers.add(addX509CRLHolder(x509CRLHolder, getCMSSignedDataRevocationOrigin()));
		}
	}

	protected void collectRevocationValues(AttributeTable attributes, ASN1ObjectIdentifier revocationValuesAttribute, RevocationOrigin origin) {
		final ASN1Encodable attValue = DSSASN1Utils.getAsn1Encodable(attributes, revocationValuesAttribute);
		RevocationValues revValues = DSSASN1Utils.getRevocationValues(attValue);
		if (revValues != null) {
			for (final CertificateList revValue : revValues.getCrlVals()) {
				addX509CRLHolder(new X509CRLHolder(revValue), origin);
			}
		}
	}

	/**
	 * Computes and store {@code CRLBinary} from {@code crlHolder}
	 * 
	 * @param crlHolder {@link X509CRLHolder} to compute values from
	 * @param origin    {@link RevocationOrigin} indicating the list where to save
	 *                  the object
	 * @return {@link CRLBinary}
	 */
	protected CRLBinary addX509CRLHolder(X509CRLHolder crlHolder, RevocationOrigin origin) {
		try {
			return addCRLBinary(crlHolder.getEncoded(), origin);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	protected void collectRevocationRefs(ASN1ObjectIdentifier revocationRefsAttribute, RevocationRefOrigin origin) {
		try {
			final ASN1Encodable attrValue = DSSASN1Utils.getAsn1Encodable(unsignedAttributes, revocationRefsAttribute);
			if (attrValue != null) {
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
			}
		} catch (Exception e) {
			// When error in computing or in format, the algorithm just continues.
			LOG.warn(
					"An error occurred during extraction of revocation references from  signature unsigned properties. "
							+ "Revocations for origin {} were not stored",
					origin.toString(), e);
		}
	}

}
