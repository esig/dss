/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.esf.CrlOcspRef;
import org.bouncycastle.asn1.esf.OcspListID;
import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;

import static eu.europa.esig.dss.spi.OID.attributeRevocationRefsOid;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_revocationRefs;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_revocationValues;

/**
 * OCSPSource that retrieves information from a {@link CMSSignedData} container.
 *
 */
@SuppressWarnings("serial")
public abstract class CMSOCSPSource extends OfflineOCSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(CMSOCSPSource.class);

	/** Store of OCSP responses */
	private final transient Store<?> ocspResponsesStore;

	/** Store of OCSPs in a basic response format */
	private final transient Store<?> ocspBasicStore;

	/** Represents unsigned properties */
	protected final transient AttributeTable unsignedAttributes;

	/**
	 * The default constructor for CAdESOCSPSource.
	 *
	 * @param cms
	 *            {@link CMSSignedData}
	 * @param unsignedAttributes
	 *            {@link AttributeTable} unsignedAttributes
	 * @deprecated since DSS 6.3. Please use {@code new CMSOCSPSource(Store<?> ocspResponsesStore,
	 *             Store<?> ocspBasicStore, AttributeTable unsignedAttributes)} constructor instead.
	 */
	@Deprecated
	protected CMSOCSPSource(final CMSSignedData cms, final AttributeTable unsignedAttributes) {
		this(cms.getOtherRevocationInfo(CMSObjectIdentifiers.id_ri_ocsp_response),
				cms.getOtherRevocationInfo(OCSPObjectIdentifiers.id_pkix_ocsp_basic), unsignedAttributes);
	}

	/**
	 * The default constructor for CAdESOCSPSource.
	 *
	 * @param ocspResponsesStore {@link Store} of OCSP responses
	 * @param ocspBasicStore {@link Store} of OCSP basic responses
	 * @param unsignedAttributes {@link AttributeTable} of the corresponding signer
	 */
	protected CMSOCSPSource(final Store<?> ocspResponsesStore, final Store<?> ocspBasicStore, final AttributeTable unsignedAttributes) {
		this.ocspResponsesStore = ocspResponsesStore;
		this.ocspBasicStore = ocspBasicStore;
		this.unsignedAttributes = unsignedAttributes;
		appendContainedOCSPResponses();
	}

	private void appendContainedOCSPResponses() {
		// Add OCSPs from SignedData
		collectFromSignedData();

		if (unsignedAttributes != null) {

			/*
			ETSI TS 101 733 V2.2.1 (2013-04) page 43
            6.3.4 revocation-values Attribute Definition
            This attribute is used to contain the revocation information required for the following forms of extended electronic
            signature: CAdES-X Long, ES X-Long Type 1, and CAdES-X Long Type 2, see clause B.1.1 for an illustration of
            this form of electronic signature.
            The revocation-values attribute is an unsigned attribute. Only a single instance of this attribute shall occur with
            an electronic signature. It holds the values of CRLs and OCSP referenced in the
            complete-revocation-references attribute.

            RevocationValues ::= SEQUENCE {
            crlVals [0] SEQUENCE OF CertificateList OPTIONAL,
            ocspVals [1] SEQUENCE OF BasicOCSPResponse OPTIONAL,
            otherRevVals [2] OtherRevVals OPTIONAL}
			 */
			collectRevocationValues(unsignedAttributes, id_aa_ets_revocationValues, RevocationOrigin.REVOCATION_VALUES);
			
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
			collectRevocationRefs(unsignedAttributes, id_aa_ets_revocationRefs,
					RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
			/*
			 * id-aa-ets-attrRevocationRefs OBJECT IDENTIFIER ::= { iso(1) member-body(2)
			 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 45} 
			 */
			collectRevocationRefs(unsignedAttributes, attributeRevocationRefsOid,
					RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS);

		}
	}

	private void collectFromSignedData() {
		addBasicOcspRespFrom_id_ri_ocsp_response();
		addBasicOcspRespFrom_id_pkix_ocsp_basic();
	}

	private void addBasicOcspRespFrom_id_ri_ocsp_response() {
		if (ocspResponsesStore == null) {
			return;
		}
		final Collection<?> otherRevocationInfoMatches = ocspResponsesStore.getMatches(null);
		for (final Object object : otherRevocationInfoMatches) {
			if (object instanceof ASN1Sequence) {
				final ASN1Sequence otherRevocationInfoMatch = (ASN1Sequence) object;
				final BasicOCSPResp basicOCSPResp;
				if (otherRevocationInfoMatch.size() == 4) {
					basicOCSPResp = DSSRevocationUtils.getBasicOcspResp(otherRevocationInfoMatch);
				} else {
					// NOTE: the expected encoding
					final OCSPResp ocspResp = DSSRevocationUtils.getOcspResp(otherRevocationInfoMatch);
					basicOCSPResp = DSSRevocationUtils.fromRespToBasic(ocspResp);
				}

				OCSPResponseBinary ocspResponseIdentifier = OCSPResponseBinary.build(basicOCSPResp);
				ocspResponseIdentifier.setAsn1ObjectIdentifier(CMSObjectIdentifiers.id_ri_ocsp_response);
				addBinary(ocspResponseIdentifier, RevocationOrigin.CMS_SIGNED_DATA);
			} else {
				LOG.warn("Unsupported object type for id_ri_ocsp_response (SHALL be an ASN1Sequence) : {}", object.getClass().getSimpleName());
			}
		}
	}

	private void addBasicOcspRespFrom_id_pkix_ocsp_basic() {
		if (ocspBasicStore == null) {
			return;
		}
		final Collection<?> otherRevocationInfoMatches = ocspBasicStore.getMatches(null);
		for (final Object object : otherRevocationInfoMatches) {
			if (object instanceof ASN1Sequence) {
				final ASN1Sequence otherRevocationInfoMatch = (ASN1Sequence) object;
				final BasicOCSPResp basicOCSPResp = DSSRevocationUtils.getBasicOcspResp(otherRevocationInfoMatch);
				if (basicOCSPResp != null) {
					OCSPResponseBinary ocspResponseIdentifier = OCSPResponseBinary.build(basicOCSPResp);
					ocspResponseIdentifier.setAsn1ObjectIdentifier(OCSPObjectIdentifiers.id_pkix_ocsp_basic);
					addBinary(ocspResponseIdentifier, RevocationOrigin.CMS_SIGNED_DATA);
				} else {
					LOG.warn("Unable to create an OCSP response from an objects. The entry is skipped.");
				}
			} else {
				LOG.warn("Unsupported object type for id_pkix_ocsp_basic (SHALL be an ASN1Sequence) : {}", object.getClass().getSimpleName());
			}
		}
	}
	
	private void collectRevocationValues(AttributeTable attributeTable, ASN1ObjectIdentifier revocationValueAttributes,
										 RevocationOrigin origin) {
		Attribute[] attributes = DSSASN1Utils.getAsn1Attributes(attributeTable, revocationValueAttributes);
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
		RevocationValues revocationValues = DSSASN1Utils.getRevocationValues(attrValue);
		if (revocationValues != null) {
			for (final BasicOCSPResponse basicOCSPResponse : revocationValues.getOcspVals()) {
				try {
					final BasicOCSPResp basicOCSPResp = new BasicOCSPResp(basicOCSPResponse);
					OCSPResponseBinary ocspResponseIdentifier = OCSPResponseBinary.build(basicOCSPResp);
					addBinary(ocspResponseIdentifier, origin);

				} catch (Exception e) {
					String errorMessage = "Unable to process OCSP binary : {}";
					if (LOG.isDebugEnabled()) {
						LOG.warn(errorMessage, e.getMessage(), e);
					} else {
						LOG.warn(errorMessage, e.getMessage());
					}
				}
			}
		}
		/*
		 * TODO: should add also OtherRevVals, but: "The syntax and semantics of the
		 * other revocation values (OtherRevVals) are outside the scope of the present
		 * document. The definition of the syntax of the other form of revocation
		 * information is as identified by OtherRevRefType."
		 */
	}

	private void collectRevocationRefs(AttributeTable unsignedAttributes,
									   ASN1ObjectIdentifier revocationReferencesAttribute, RevocationRefOrigin origin) {
		final Attribute[] attributes = DSSASN1Utils.getAsn1Attributes(unsignedAttributes, revocationReferencesAttribute);
		if (Utils.isArrayEmpty(attributes)) {
			return;
		}
		for (Attribute attribute : attributes) {
			final ASN1Set attrValues = attribute.getAttrValues();
			if (attrValues.size() <= 0) {
				return;
			}

			final ASN1Encodable attrValue = attrValues.getObjectAt(0);
			final ASN1Sequence revocationRefs = (ASN1Sequence) attrValue;
			for (int i = 0; i < revocationRefs.size(); i++) {
				try {
					final CrlOcspRef otherCertId = CrlOcspRef.getInstance(revocationRefs.getObjectAt(i));
					final OcspListID ocspListID = otherCertId.getOcspids();
					if (ocspListID != null) {
						for (final OcspResponsesID ocspResponsesID : ocspListID.getOcspResponses()) {
							final OCSPRef ocspRef = new OCSPRef(ocspResponsesID);
							addRevocationReference(ocspRef, origin);
						}
					}
				} catch (Exception e) {
					String errorMessage = "Unable to process OCSP reference : {}";
					if (LOG.isDebugEnabled()) {
						LOG.warn(errorMessage, e.getMessage(), e);
					} else {
						LOG.warn(errorMessage, e.getMessage());
					}
				}
			}
		}
	}

}
