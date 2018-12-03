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
package eu.europa.esig.dss.cades.signature;

import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_contentHint;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_contentIdentifier;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_commitmentType;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_contentTimestamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_sigPolicyId;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_signerAttr;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_signerLocation;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_signingTime;

import java.util.ArrayList;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.Random;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import org.bouncycastle.asn1.esf.SigPolicyQualifierInfo;
import org.bouncycastle.asn1.esf.SigPolicyQualifiers;
import org.bouncycastle.asn1.esf.SignaturePolicyId;
import org.bouncycastle.asn1.esf.SignaturePolicyIdentifier;
import org.bouncycastle.asn1.esf.SignerAttribute;
import org.bouncycastle.asn1.esf.SignerLocation;
import org.bouncycastle.asn1.ess.ContentHints;
import org.bouncycastle.asn1.ess.ContentIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Time;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.OID;
import eu.europa.esig.dss.Policy;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.SignerAttributeV2;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.TimestampToken;

/**
 * This class holds the CAdES-B signature profile; it supports the inclusion of the mandatory signed
 * id_aa_ets_sigPolicyId attribute as specified in ETSI TS 101
 * 733 V1.8.1, clause 5.8.1.
 *
 *
 *
 */
public class CAdESLevelBaselineB {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESLevelBaselineB.class);

	private final boolean padesUsage;

	/**
	 * The default constructor for CAdESLevelBaselineB.
	 */
	public CAdESLevelBaselineB() {
		this(false);
	}

	/**
	 * The default constructor for CAdESLevelBaselineB.
	 */
	public CAdESLevelBaselineB(boolean padesUsage) {
		this.padesUsage = padesUsage;
	}

	/**
	 * Return the table of unsigned properties.
	 *
	 * @return
	 */
	public AttributeTable getUnsignedAttributes() {
		return new AttributeTable(new Hashtable<ASN1ObjectIdentifier, ASN1Encodable>());
	}

	public AttributeTable getSignedAttributes(final CAdESSignatureParameters parameters) {
		if (parameters.getSignedData() != null) {
			LOG.debug("Using explict SignedAttributes from parameter");
			return CMSUtils.getAttributesFromByteArray(parameters.getSignedData());
		}

		ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
		addSigningCertificateAttribute(parameters, signedAttributes);
		addSigningTimeAttribute(parameters, signedAttributes);
		addSignerAttribute(parameters, signedAttributes);
		addSignaturePolicyId(parameters, signedAttributes);
		addContentHints(parameters, signedAttributes);
		addContentIdentifier(parameters, signedAttributes);
		addCommitmentType(parameters, signedAttributes);
		addSignerLocation(parameters, signedAttributes);
		addContentTimestamps(parameters, signedAttributes);

		// mime-type attribute breaks parallel signatures by adding PKCS7 as a mime-type for subsequent signers.
		// This attribute is not mandatory, so it has been disabled.

		final AttributeTable signedAttributesTable = new AttributeTable(signedAttributes);
		return signedAttributesTable;
	}

	/**
	 * ETSI TS 101 733 V2.2.1 (2013-04)
	 * 5.11.3 signer-attributes Attribute
	 * NOTE 1: Only a single signer-attributes can be used.
	 *
	 * The signer-attributes attribute specifies additional attributes of the signer (e.g. role).
	 * It may be either:
	 * • claimed attributes of the signer; or
	 * • certified attributes of the signer.
	 * The signer-attributes attribute shall be a signed attribute.
	 *
	 * @param parameters
	 * @param signedAttributes
	 * @return
	 */
	private void addSignerAttribute(final CAdESSignatureParameters parameters, final ASN1EncodableVector signedAttributes) {
		final List<String> claimedSignerRoles = parameters.bLevel().getClaimedSignerRoles();
		if (claimedSignerRoles != null) {

			List<org.bouncycastle.asn1.x509.Attribute> claimedAttributes = new ArrayList<org.bouncycastle.asn1.x509.Attribute>(claimedSignerRoles.size());
			for (final String claimedSignerRole : claimedSignerRoles) {
				final DERUTF8String roles = new DERUTF8String(claimedSignerRole);
				final org.bouncycastle.asn1.x509.Attribute id_aa_ets_signerAttr = new org.bouncycastle.asn1.x509.Attribute(OID.id_at_role,
						new DERSet(roles));
				claimedAttributes.add(id_aa_ets_signerAttr);
			}
			org.bouncycastle.asn1.cms.Attribute signerAttributes;
			if (!parameters.isEn319122()) {
				signerAttributes = new org.bouncycastle.asn1.cms.Attribute(id_aa_ets_signerAttr,
						new DERSet(new SignerAttribute(claimedAttributes.toArray(new org.bouncycastle.asn1.x509.Attribute[claimedAttributes.size()]))));
			} else {
				signerAttributes = new org.bouncycastle.asn1.cms.Attribute(OID.id_aa_ets_signerAttrV2,
						new DERSet(new SignerAttributeV2(claimedAttributes.toArray(new org.bouncycastle.asn1.x509.Attribute[claimedAttributes.size()]))));
			}
			signedAttributes.add(signerAttributes);
		}
	}

	private void addSigningTimeAttribute(final CAdESSignatureParameters parameters, final ASN1EncodableVector signedAttributes) {
		/*
		 * In PAdES, we don't include the signing time : ETSI TS 102 778-3 V1.2.1
		 * (2010-07): 4.5.3 signing-time Attribute
		 */
		if (padesUsage) {
			return;
		}

		final Date signingDate = parameters.bLevel().getSigningDate();
		if (signingDate != null) {
			final DERSet attrValues = new DERSet(new Time(signingDate));
			final Attribute attribute = new Attribute(pkcs_9_at_signingTime, attrValues);
			signedAttributes.add(attribute);
		}
	}

	/**
	 * ETSI TS 101 733 V2.2.1 (2013-04)
	 * 5.11.2 signer-location Attribute
	 * The signer-location attribute specifies a mnemonic for an address associated with the signer at a particular
	 * geographical (e.g. city) location. The mnemonic is registered in the country in which the signer is located and
	 * is used in
	 * the provision of the Public Telegram Service (according to Recommendation ITU-T F.1 [11]).
	 * The signer-location attribute shall be a signed attribute.
	 *
	 * @param parameters
	 * @param signedAttributes
	 * @return
	 */
	private void addSignerLocation(final CAdESSignatureParameters parameters, final ASN1EncodableVector signedAttributes) {
		/*
		 * In PAdES, the role is in the signature dictionary
		 */
		if (padesUsage) {
			return;
		}

		final eu.europa.esig.dss.SignerLocation signerLocationParameter = parameters.bLevel().getSignerLocation();
		if (signerLocationParameter != null) {

			final DERUTF8String country = signerLocationParameter.getCountry() == null ? null : new DERUTF8String(signerLocationParameter.getCountry());
			final DERUTF8String locality = signerLocationParameter.getLocality() == null ? null : new DERUTF8String(signerLocationParameter.getLocality());
			final ASN1EncodableVector postalAddress = new ASN1EncodableVector();
			final List<String> postalAddressParameter = signerLocationParameter.getPostalAddress();
			if (postalAddressParameter != null) {
				for (final String addressLine : postalAddressParameter) {
					postalAddress.add(new DERUTF8String(addressLine));
				}
			}
			final DERSequence derSequencePostalAddress = new DERSequence(postalAddress);
			final SignerLocation signerLocation = new SignerLocation(country, locality, derSequencePostalAddress);
			final DERSet attrValues = new DERSet(signerLocation);
			final Attribute attribute = new Attribute(id_aa_ets_signerLocation, attrValues);
			signedAttributes.add(attribute);
		}
	}

	/**
	 * ETSI TS 101 733 V2.2.1 (2013-04)
	 *
	 * 5.11.1 commitment-type-indication Attribute
	 * There may be situations where a signer wants to explicitly indicate to a verifier that by signing the data, it
	 * illustrates a
	 * type of commitment on behalf of the signer. The commitment-type-indication attribute conveys such
	 * information.
	 *
	 * @param parameters
	 * @param signedAttributes
	 */
	private void addCommitmentType(final CAdESSignatureParameters parameters, final ASN1EncodableVector signedAttributes) {

		// TODO (19/08/2014): commitmentTypeQualifier is not implemented
		final List<String> commitmentTypeIndications = parameters.bLevel().getCommitmentTypeIndications();
		if (Utils.isCollectionNotEmpty(commitmentTypeIndications)) {

			final int size = commitmentTypeIndications.size();
			ASN1Encodable[] asn1Encodables = new ASN1Encodable[size];
			for (int ii = 0; ii < size; ii++) {

				final String commitmentTypeId = commitmentTypeIndications.get(ii);
				final ASN1ObjectIdentifier objectIdentifier = new ASN1ObjectIdentifier(commitmentTypeId);
				// final CommitmentTypeIndication commitmentTypeIndication = new
				// CommitmentTypeIndication(objectIdentifier);
				// final ASN1Primitive asn1Primitive = commitmentTypeIndication.toASN1Primitive();
				asn1Encodables[ii] = new DERSequence(objectIdentifier);
			}
			final DERSet attrValues = new DERSet(asn1Encodables);
			final Attribute attribute = new Attribute(id_aa_ets_commitmentType, attrValues);
			signedAttributes.add(attribute);
		}
	}

	/**
	 * A content time-stamp allows a time-stamp token of the data to be signed to be incorporated into the signed
	 * information.
	 * It provides proof of the existence of the data before the signature was created.
	 *
	 * A content time-stamp attribute is the time-stamp token of the signed data content before it is signed.
	 * This attribute is a signed attribute.
	 * Its object identifier is :
	 * id-aa-ets-contentTimestamp OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
	 * smime(16) id-aa(2) 20}
	 *
	 * Content time-stamp attribute values have ASN.1 type ContentTimestamp:
	 * ContentTimestamp ::= TimeStampToken
	 *
	 * The value of messageImprint of TimeStampToken (as described in RFC 3161) is the hash of the message digest as
	 * defined in
	 * ETSI standard 101733 v.2.2.1, clause 5.6.1.
	 *
	 * NOTE: content-time-stamp indicates that the signed information was formed before the date included in the
	 * content-time-stamp.
	 * NOTE (bis): There is a small difference in treatment between the content-time-stamp and the archive-timestamp
	 * (ATSv2) when the signature
	 * is attached. In that case, the content-time-stamp is computed on the raw data (without ASN.1 tag and length)
	 * whereas the archive-timestamp
	 * is computed on data as read.
	 *
	 * @param parameters
	 * @param signedAttributes
	 * @return
	 */
	private void addContentTimestamps(final CAdESSignatureParameters parameters, final ASN1EncodableVector signedAttributes) {

		if (Utils.isCollectionNotEmpty(parameters.getContentTimestamps())) {

			final List<TimestampToken> contentTimestamps = parameters.getContentTimestamps();
			for (final TimestampToken contentTimestamp : contentTimestamps) {

				final ASN1Object asn1Object = DSSASN1Utils.toASN1Primitive(contentTimestamp.getEncoded());
				final DERSet attrValues = new DERSet(asn1Object);
				final Attribute attribute = new Attribute(id_aa_ets_contentTimestamp, attrValues);
				signedAttributes.add(attribute);
			}
		}
	}

	/**
	 * ETSI TS 101 733 V2.2.1 (2013-04)
	 *
	 * 5.10.3 content-hints Attribute
	 * The content-hints attribute provides information on the innermost signed content of a multi-layer message where
	 * one content is encapsulated in another.
	 * The syntax of the content-hints attribute type of the ES is as defined in ESS (RFC 2634 [5]).
	 * When used to indicate the precise format of the data to be presented to the user, the following rules apply:
	 * • the contentType indicates the type of the associated content. It is an object identifier (i.e. a unique string
	 * of
	 * integers) assigned by an authority that defines the content type; and
	 * • when the contentType is id-data the contentDescription shall define the presentation format; the
	 * format may be defined by MIME types.
	 * When the format of the content is defined by MIME types, the following rules apply:
	 * • the contentType shall be id-data as defined in CMS (RFC 3852 [4]);
	 * • the contentDescription shall be used to indicate the encoding of the data, in accordance with the rules
	 * defined RFC 2045 [6]; see annex F for an example of structured contents and MIME.
	 * NOTE 1: id-data OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 1 }.
	 * NOTE 2: contentDescription is optional in ESS (RFC 2634 [5]). It may be used to complement
	 * contentTypes defined elsewhere; such definitions are outside the scope of the present document.
	 *
	 * @param parameters
	 * @param signedAttributes
	 * @return
	 */
	private void addContentHints(final CAdESSignatureParameters parameters, final ASN1EncodableVector signedAttributes) {
		if (Utils.isStringNotBlank(parameters.getContentHintsType())) {

			final ASN1ObjectIdentifier contentHintsType = new ASN1ObjectIdentifier(parameters.getContentHintsType());
			final String contentHintsDescriptionString = parameters.getContentHintsDescription();
			final DERUTF8String contentHintsDescription = Utils.isStringBlank(contentHintsDescriptionString) ? null
					: new DERUTF8String(contentHintsDescriptionString);
			// "text/plain";
			// "1.2.840.113549.1.7.1";

			final ContentHints contentHints = new ContentHints(contentHintsType, contentHintsDescription);
			final DERSet attrValues = new DERSet(contentHints);
			final Attribute attribute = new Attribute(id_aa_contentHint, attrValues);
			signedAttributes.add(attribute);
		}
	}

	/**
	 * ETSI TS 101 733 V2.2.1 (2013-04)
	 *
	 * 5.10.2 content-identifier Attribute
	 * The content-identifier attribute provides an identifier for the signed content, for use when a reference may be
	 * later required to that content; for example, in the content-reference attribute in other signed data sent later.
	 * The
	 * content-identifier shall be a signed attribute. content-identifier attribute type values for the ES have an ASN.1
	 * type ContentIdentifier, as defined in
	 * ESS (RFC 2634 [5]).
	 *
	 * The minimal content-identifier attribute should contain a concatenation of user-specific identification
	 * information (such as a user name or public keying material identification information), a GeneralizedTime string,
	 * and a random number.
	 *
	 * @param parameters
	 * @param signedAttributes
	 */
	private void addContentIdentifier(final CAdESSignatureParameters parameters, final ASN1EncodableVector signedAttributes) {
		/* this attribute is prohibited in PAdES B */
		if (padesUsage) {
			return;
		}

		final String contentIdentifierPrefix = parameters.getContentIdentifierPrefix();
		if (Utils.isStringNotBlank(contentIdentifierPrefix)) {

			final String contentIdentifierSuffix;
			if (Utils.isStringBlank(parameters.getContentIdentifierSuffix())) {

				final Date now = new Date();
				final String asn1GeneralizedTimeString = new ASN1GeneralizedTime(now).getTimeString();
				final long randomNumber = new Random(now.getTime()).nextLong();
				contentIdentifierSuffix = asn1GeneralizedTimeString + randomNumber;
				parameters.setContentIdentifierSuffix(contentIdentifierSuffix);
			} else {
				contentIdentifierSuffix = parameters.getContentIdentifierSuffix();
			}
			final String contentIdentifierString = contentIdentifierPrefix + contentIdentifierSuffix;
			final ContentIdentifier contentIdentifier = new ContentIdentifier(contentIdentifierString.getBytes());
			final DERSet attrValues = new DERSet(contentIdentifier);
			final Attribute attribute = new Attribute(id_aa_contentIdentifier, attrValues);
			signedAttributes.add(attribute);
		}
	}

	private void addSignaturePolicyId(final CAdESSignatureParameters parameters, final ASN1EncodableVector signedAttributes) {

		Policy policy = parameters.bLevel().getSignaturePolicy();
		if (policy != null) {

			final String policyId = policy.getId();
			SignaturePolicyIdentifier sigPolicy = null;

			if (Utils.isStringEmpty(policyId)) {// implicit
				sigPolicy = new SignaturePolicyIdentifier();
			} else { // explicit
				final ASN1ObjectIdentifier derOIPolicyId = new ASN1ObjectIdentifier(policyId);
				final ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(policy.getDigestAlgorithm().getOid());
				final AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(oid);
				OtherHashAlgAndValue otherHashAlgAndValue = new OtherHashAlgAndValue(algorithmIdentifier, new DEROctetString(policy.getDigestValue()));

				if (Utils.isStringNotEmpty(policy.getSpuri())) {
					SigPolicyQualifierInfo policyQualifierInfo = new SigPolicyQualifierInfo(PKCSObjectIdentifiers.id_spq_ets_uri,
							new DERUTF8String(policy.getSpuri()));
					SigPolicyQualifierInfo[] qualifierInfos = new SigPolicyQualifierInfo[] { policyQualifierInfo };
					SigPolicyQualifiers qualifiers = new SigPolicyQualifiers(qualifierInfos);

					sigPolicy = new SignaturePolicyIdentifier(new SignaturePolicyId(derOIPolicyId, otherHashAlgAndValue, qualifiers));
				} else {
					sigPolicy = new SignaturePolicyIdentifier(new SignaturePolicyId(derOIPolicyId, otherHashAlgAndValue));
				}
			}

			final DERSet attrValues = new DERSet(sigPolicy);
			final Attribute attribute = new Attribute(id_aa_ets_sigPolicyId, attrValues);
			signedAttributes.add(attribute);
		}
	}

	private void addSigningCertificateAttribute(final CAdESSignatureParameters parameters, final ASN1EncodableVector signedAttributes) {
		if (parameters.getSigningCertificate() == null && parameters.isGenerateTBSWithoutCertificate()) {
			LOG.debug("Signing certificate not available and must be added to signed attributes later");
			return;
		}

		CMSUtils.addSigningCertificateAttribute(signedAttributes, parameters.getDigestAlgorithm(), parameters.getSigningCertificate());
	}

}
