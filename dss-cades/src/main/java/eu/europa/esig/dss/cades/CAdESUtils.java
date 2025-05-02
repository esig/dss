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
package eu.europa.esig.dss.cades;

import eu.europa.esig.dss.cades.signature.CustomMessageDigestCalculatorProvider;
import eu.europa.esig.dss.cades.validation.PrecomputedDigestCalculatorProvider;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.resources.InMemoryResourcesHandlerBuilder;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.OtherRevocationInfoFormat;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampChain;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSProcessableFile;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.Objects;

import static eu.europa.esig.dss.spi.OID.id_aa_ATSHashIndex;
import static eu.europa.esig.dss.spi.OID.id_aa_ATSHashIndexV2;
import static eu.europa.esig.dss.spi.OID.id_aa_ATSHashIndexV3;
import static eu.europa.esig.dss.spi.OID.id_aa_er_external;
import static eu.europa.esig.dss.spi.OID.id_aa_er_internal;
import static eu.europa.esig.dss.spi.OID.id_aa_ets_archiveTimestampV2;
import static eu.europa.esig.dss.spi.OID.id_aa_ets_archiveTimestampV3;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_contentTimestamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_escTimeStamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signingCertificate;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signingCertificateV2;

/**
 * The utils for dealing with CMS and related objects
 *
 */
public final class CAdESUtils {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESUtils.class);

	/** The default DigestAlgorithm for ArchiveTimestamp */
	public static final DigestAlgorithm DEFAULT_ARCHIVE_TIMESTAMP_HASH_ALGO = DigestAlgorithm.SHA256;

	/** 01-01-1950 date, see RFC 3852 (month param is zero-based (i.e. 0 for January)) */
	private static final Date JANUARY_1950 = DSSUtils.getUtcDate(1950, 0, 1);

	/** 01-01-2050 date, see RFC 3852 (month param is zero-based (i.e. 0 for January)) */
	private static final Date JANUARY_2050 = DSSUtils.getUtcDate(2050, 0, 1);

	/** The default resources handler builder to be used across the code */
	public static final InMemoryResourcesHandlerBuilder DEFAULT_RESOURCES_HANDLER_BUILDER = new InMemoryResourcesHandlerBuilder();

	/** Contains a list of all CAdES timestamp OIDs */
	private static List<ASN1ObjectIdentifier> timestampOids;

	/** Contains a list of all CAdES evidence record OIDs */
	private static List<ASN1ObjectIdentifier> evidenceRecordOids;

	static {
		timestampOids = new ArrayList<>();
		timestampOids.add(id_aa_ets_contentTimestamp);
		timestampOids.add(id_aa_ets_archiveTimestampV2);
		timestampOids.add(id_aa_ets_archiveTimestampV3);
		timestampOids.add(id_aa_ets_certCRLTimestamp);
		timestampOids.add(id_aa_ets_escTimeStamp);
		timestampOids.add(id_aa_signatureTimeStampToken);

		evidenceRecordOids = new ArrayList<>();
		evidenceRecordOids.add(id_aa_er_internal);
		evidenceRecordOids.add(id_aa_er_external);
	}

	/**
	 * Utils class
	 */
	private CAdESUtils() {
		// empty
	}

	/**
	 * This method generate {@code CMSSignedData} using the provided #{@code CMSSignedDataGenerator}, the content and
	 * the indication if the content should be encapsulated.
	 *
	 * @param generator {@link CMSSignedDataGenerator}
	 * @param content {@link CMSTypedData}
	 * @param encapsulate true if the content should be encapsulated in the signature, false otherwise
	 * @return {@link CMSSignedData}
	 * @deprecated since DSS 6.3. To be removed.
	 */
	@Deprecated
	public static CMSSignedData generateCMSSignedData(final CMSSignedDataGenerator generator,
													  final CMSTypedData content, final boolean encapsulate) {
		try {
			return generator.generate(content, encapsulate);
		} catch (CMSException e) {
			throw new DSSException("Unable to generate the CMSSignedData", e);
		}
	}

	/**
	 * Generates a counter signature
	 *
	 * @param cmsSignedDataGenerator {@link CMSSignedDataGenerator} to extend the CMS SignedData
	 * @param signerInfoToSign {@link SignerInformation} to be counter-signed
	 * @return {@link SignerInformationStore} with a counter signature
	 * @deprecated since DSS 6.3. To be removed.
	 */
	@Deprecated
	public static SignerInformationStore generateCounterSigners(CMSSignedDataGenerator cmsSignedDataGenerator,
																SignerInformation signerInfoToSign) {
		try {
			return cmsSignedDataGenerator.generateCounterSigners(signerInfoToSign);
		} catch (CMSException e) {
			throw new DSSException("Unable to generate the SignerInformationStore for the counter-signature", e);
		}
	}

	/**
	 * Generates a detached CMS SignedData
	 *
	 * @param generator {@link CMSSignedDataGenerator}
	 * @param content {@link CMSProcessableByteArray} to sign
	 * @return {@link CMSSignedData}
	 * @deprecated since DSS 6.3. To be removed.
	 */
	@Deprecated
	public static CMSSignedData generateDetachedCMSSignedData(final CMSSignedDataGenerator generator,
															  final CMSProcessableByteArray content) {
		try {
			return generator.generate(content, false);
		} catch (CMSException e) {
			throw new DSSException("Unable to generate the CMSSignedData", e);
		}
	}

	/**
	 * This method is used to ensure the presence of all items from SignedData.digestAlgorithm set
	 * from {@code oldCmsSignedData} within {@code newCmsSignedData}
	 *
	 * @param newCmsSignedData {@link CMSSignedData} to be extended with digest algorithms, if required
 	 * @param oldCmsSignedData {@link CMSSignedData} to copy digest algorithms set from
	 * @return extended {@link CMSSignedData}
	 * @deprecated since DSS 6.3. See {@code CMSUtils#populateDigestAlgorithmSet}
	 */
	@Deprecated
	public static CMSSignedData populateDigestAlgorithmSet(CMSSignedData newCmsSignedData,
														   CMSSignedData oldCmsSignedData) {
		if (oldCmsSignedData != null) {
			for (AlgorithmIdentifier algorithmIdentifier : oldCmsSignedData.getDigestAlgorithmIDs()) {
				newCmsSignedData = CMSSignedData.addDigestAlgorithm(newCmsSignedData, algorithmIdentifier);
			}
		}
		return newCmsSignedData;
	}

	/**
	 * This method adds a DigestAlgorithm used by an Archive TimeStamp to
	 * the SignedData.digestAlgorithms set, when required.
	 * <p>
	 * See ETSI EN 319 122-1, ch. "5.5.3 The archive-time-stamp-v3 attribute"
	 *
	 * @param cmsSignedData {@link CMSSignedData} to extend
	 * @param algorithmIdentifier {@link AlgorithmIdentifier} to add
	 * @return {@link CMSSignedData}
	 * @deprecated since DSS 6.3. See {@code CMSUtils#populateDigestAlgorithmSet}
	 */
	@Deprecated
	public static CMSSignedData addDigestAlgorithm(CMSSignedData cmsSignedData, AlgorithmIdentifier algorithmIdentifier) {
		return CMSSignedData.addDigestAlgorithm(cmsSignedData, algorithmIdentifier);
	}

	/**
	 * Gets the DER SignedAttributes table from the given {@code SignerInformation}
	 *
	 * @param signerInformation
	 *            {@code SignerInformation}
	 * @return {@code DERTaggedObject} representing the signed attributes
	 */
	public static DERTaggedObject getDERSignedAttributes(final SignerInformation signerInformation) {
		try {
			final byte[] encodedSignedAttributes = signerInformation.getEncodedSignedAttributes();
			if (encodedSignedAttributes == null) {
				return null;
			}
			final ASN1Set asn1Set = DSSASN1Utils.toASN1Primitive(encodedSignedAttributes);
			return new DERTaggedObject(false, 0, asn1Set);
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to extract SignedAttributes. Reason : %s", e.getMessage()), e);
		}
	}

	/**
	 * This method returns the signed content extracted from a CMSTypedData
	 * 
	 * @param cmsTypedData
	 *            {@code CMSTypedData} cannot be null
	 * @return the signed content extracted from {@code CMSTypedData}
	 * @deprecated since DSS 6.3. To be removed.
	 */
	@Deprecated
	public static byte[] getSignedContent(final CMSTypedData cmsTypedData) {
		if (cmsTypedData == null) {
			throw new DSSException("CMSTypedData is null (should be a detached signature)");
		}
		try (ByteArrayOutputStream originalDocumentData = new ByteArrayOutputStream()) {
			cmsTypedData.write(originalDocumentData);
			return originalDocumentData.toByteArray();
		} catch (CMSException | IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method returns the existing unsigned attributes or a new empty attributes hashtable
	 *
	 * @param signerInformation
	 *            the signer information
	 * @return the existing unsigned attributes or an empty attributes hashtable
	 */
	public static AttributeTable getUnsignedAttributes(final SignerInformation signerInformation) {
		final AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
		return emptyIfNull(unsignedAttributes);
	}

	/**
	 * This method returns the existing signed attributes or a new empty attributes hashtable
	 *
	 * @param signerInformation
	 *            the signer information
	 * @return the existing signed attributes or an empty attributes {@code Hashtable}
	 */
	public static AttributeTable getSignedAttributes(final SignerInformation signerInformation) {
		final AttributeTable signedAttributes = signerInformation.getSignedAttributes();
		return emptyIfNull(signedAttributes);
	}

	/**
	 * This method returns an AttributeTable parsed from ASN.1 encoded representation
	 *
	 * @param encodedAttributes
	 *            ASN.1 encoded AttributesTable
	 * @return AttributeTable created from given encodedAttributes
	 */
	public static AttributeTable getAttributesFromByteArray(final byte[] encodedAttributes) {
		DLSet dlSet;
		try (ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(encodedAttributes))) {
			dlSet = (DLSet) asn1InputStream.readObject();
		} catch (IOException e) {
			throw new DSSException("Error while reading ASN.1 encoded attributes", e);
		}
		return new AttributeTable(dlSet);
	}

	/**
	 * Method to add signing certificate to ASN.1 DER encoded signed attributes. Certificate
	 * will be added as either signing-certificate or signing-certificate-v2 attribute depending
	 * on digest algorithm being used.
	 *
	 * @param signedAttributes
	 *            Signed attributes to append signing certificate to
	 * @param digestAlgorithm
	 *            the digest algorithm to be used
	 * @param signingToken
	 *            The signing certificate to be appended
	 */
	public static void addSigningCertificateAttribute(final ASN1EncodableVector signedAttributes, final DigestAlgorithm digestAlgorithm,
			CertificateToken signingToken) {

		final IssuerSerial issuerSerial = DSSASN1Utils.getIssuerSerial(signingToken);

		final byte[] certHash = signingToken.getDigest(digestAlgorithm);
		if (LOG.isDebugEnabled()) {
			LOG.debug("Adding Certificate Hash {} with algorithm {}", Utils.toHex(certHash), digestAlgorithm.getName());
		}

		Attribute attribute;
		if (digestAlgorithm == DigestAlgorithm.SHA1) {
			final ESSCertID essCertID = new ESSCertID(certHash, issuerSerial);
			SigningCertificate signingCertificate = new SigningCertificate(essCertID);
			attribute = new Attribute(id_aa_signingCertificate, new DERSet(signingCertificate));
		} else {
			ESSCertIDv2 essCertIdv2;
			if (DigestAlgorithm.SHA256 == digestAlgorithm) {
				// SHA-256 is default
				essCertIdv2 = new ESSCertIDv2(null, certHash, issuerSerial);
			} else {
				essCertIdv2 = new ESSCertIDv2(DSSASN1Utils.getAlgorithmIdentifier(digestAlgorithm), certHash, issuerSerial);
			}
			SigningCertificateV2 signingCertificateV2 = new SigningCertificateV2(essCertIdv2);
			attribute = new Attribute(id_aa_signingCertificateV2, new DERSet(signingCertificateV2));
		}
		signedAttributes.add(attribute);
	}
	
	/**
	 * Compares two CMSSignedData objects by their encoded binaries
	 * 
	 * @param signedData {@link CMSSignedData} object to compare
	 * @param signedDataToCompare {@link CMSSignedData} object to compare with
	 * @return true if binaries of two CMSSignedData are equal, false otherwise
	 * @throws IOException if an exception occurs
	 */
	public static boolean isCMSSignedDataEqual(CMSSignedData signedData, CMSSignedData signedDataToCompare) throws IOException {
		return Arrays.equals(signedData.getEncoded(), signedDataToCompare.getEncoded());
	}

	/**
	 * Returns a signed attribute with the given {@code oid} from {@code signerInformation} if present and unique.
	 * If multiple Attributes extraction is expected, please use
	 * {@code #getSignedAttributes(signerInformation, oid)} method.
	 *
	 * @param signerInformation {@link SignerInformation} containing signed attributes
	 * @param oid {@link ASN1ObjectIdentifier} oid of the element to extract
	 * @return {@link Attribute} with the given OID
	 */
	public static Attribute getSignedAttribute(final SignerInformation signerInformation, ASN1ObjectIdentifier oid) {
		Attribute[] attributes = getSignedAttributes(signerInformation, oid);
		if (Utils.isArrayEmpty(attributes)) {
			return null;
		}
		if (Utils.arraySize(attributes) > 1) {
			LOG.warn("More than attribute with OID '{}' found in signed attributes table! Value is skipped.", oid);
			return null;
		}
		return attributes[0];
	}

	/**
	 * Returns signed attributes matching the given {@code oid} from {@code signerInformation} if present.
	 * Otherwise, returns an empty array.
	 *
	 * @param signerInformation {@link SignerInformation} containing signed attributes
	 * @param oid {@link ASN1ObjectIdentifier} oid of the elements to extract
	 * @return an array of {@link Attribute}s with the given OID
	 */
	public static Attribute[] getSignedAttributes(final SignerInformation signerInformation, ASN1ObjectIdentifier oid) {
		AttributeTable attributeTable = getSignedAttributes(signerInformation);
		return DSSASN1Utils.getAsn1Attributes(attributeTable, oid);
	}

	/**
	 * Returns an unsigned attribute with the given {@code oid} from {@code signerInformation} if present and unique.
	 * If multiple Attributes extraction is expected, please use
	 * {@code #getUnsignedAttributes(signerInformation, oid)} method.
	 *
	 * @param signerInformation {@link SignerInformation} to get attribute from
	 * @param oid {@link ASN1ObjectIdentifier} of the target attribute
	 * @return {@link Attribute}
	 */
	public static Attribute getUnsignedAttribute(SignerInformation signerInformation, ASN1ObjectIdentifier oid) {
		Attribute[] attributes = getUnsignedAttributes(signerInformation, oid);
		if (Utils.isArrayEmpty(attributes)) {
			return null;
		}
		if (Utils.arraySize(attributes) > 1) {
			LOG.warn("More than attribute with OID '{}' found in unsigned attributes table! Value is skipped.", oid);
			return null;
		}
		return attributes[0];
	}

	/**
	 * Returns unsigned attributes matching the given {@code oid} from {@code signerInformation} if present.
	 * Otherwise, returns an empty array.
	 *
	 * @param signerInformation {@link SignerInformation} containing unsigned attributes
	 * @param oid {@link ASN1ObjectIdentifier} oid of the elements to extract
	 * @return an array of {@link Attribute}s with the given OID
	 */
	public static Attribute[] getUnsignedAttributes(final SignerInformation signerInformation, ASN1ObjectIdentifier oid) {
		AttributeTable attributeTable = getUnsignedAttributes(signerInformation);
		return DSSASN1Utils.getAsn1Attributes(attributeTable, oid);
	}

	/**
	 * Checks if the signature is detached
	 * @param cmsSignedData {@link CMSSignedData}
	 * @return TRUE if the signature is detached, FALSE otherwise
	 * @deprecated since DSS 6.3. See {@code cmsSignedData.isDetachedSignature()}
	 */
	@Deprecated
	public static boolean isDetachedSignature(CMSSignedData cmsSignedData) {
		return cmsSignedData.isDetachedSignature();
	}
	
	/**
	 * Returns the original document from the provided {@code CMS}
	 *
	 * @param cms {@link CMS} to get original document from
	 * @param detachedDocuments list of {@link DSSDocument}s
	 * @return original {@link DSSDocument}
	 */
	public static DSSDocument getOriginalDocument(CMS cms, List<DSSDocument> detachedDocuments) {
		Objects.requireNonNull(cms, "CMS shall be provided!");

		if (!cms.isDetachedSignature()) {
			final DSSDocument signedContent = cms.getSignedContent();
			if (signedContent == null) {
				throw new DSSException("No signed content found within enveloping CMS signature!");
			}
			return signedContent;

		} else if (Utils.collectionSize(detachedDocuments) == 1) {
			return detachedDocuments.get(0);

		} else {
			throw new DSSException("Detached content is not provided or cannot be identified (only one document shall be provided)!");
		}
	}

	/**
	 * Returns the content to be signed
	 *
	 * @param toSignData {@link DSSDocument} to sign
	 * @return {@link CMSTypedData}
	 * @deprecated since DSS 6.3. See {@code CMSUtils#toCMSEncapsulatedContent(DSSDocument document)}
	 */
	@Deprecated
	public static CMSTypedData getContentToBeSigned(final DSSDocument toSignData) {
		Objects.requireNonNull(toSignData, "Document to be signed is missing");
		CMSTypedData content;
		if (toSignData instanceof DigestDocument) {
			content = new CMSAbsentContent();
		} else if (toSignData instanceof FileDocument) {
			FileDocument fileDocument = (FileDocument) toSignData;
			content = new CMSProcessableFile(fileDocument.getFile());
		} else {
			content = new CMSProcessableByteArray(DSSUtils.toByteArray(toSignData));
		}
		return content;
	}

	/**
	 * Returns a {@code DigestCalculatorProvider}
	 *
	 * @param toSignDocument {@link DSSDocument} to sign
	 * @param digestAlgorithm {@link DigestAlgorithm} to use
	 * @return {@link DigestCalculatorProvider}
	 */
	public static DigestCalculatorProvider getDigestCalculatorProvider(DSSDocument toSignDocument,
																	   DigestAlgorithm digestAlgorithm) {
		if (digestAlgorithm != null) {
			return new CustomMessageDigestCalculatorProvider(digestAlgorithm, toSignDocument.getDigestValue(digestAlgorithm));
		} else if (toSignDocument instanceof DigestDocument) {
			return new PrecomputedDigestCalculatorProvider((DigestDocument) toSignDocument);
		}
		return new BcDigestCalculatorProvider();
	}

	/**
	 * Checks if the given {@code SignerInformation}'s unsignedProperties contain an archive-time-stamp (ATSv2) element
	 * 
	 * @param signerInformation {@link SignerInformation} to check
	 * @return TRUE if the signerInformation contains an ATSv2, FALSE otherwise
	 */
	public static boolean containsATSTv2(SignerInformation signerInformation) {
		AttributeTable unsignedAttributes = getUnsignedAttributes(signerInformation);
		Attribute[] attributes = unsignedAttributes.toASN1Structure().getAttributes();
		for (final Attribute attribute : attributes) {
			if (isAttributeOfType(attribute, OID.id_aa_ets_archiveTimestampV2)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Reads the SigningDate with respect to the RFC 3852
	 *
	 * @param attrValue {@link ASN1Encodable} containing the signingDate
	 * @return {@link Date} if its format is correct, null otherwise
	 */
	public static Date readSigningDate(final ASN1Encodable attrValue) {
		if (attrValue != null) {
			final Date signingDate = DSSASN1Utils.getDate(attrValue);
			if (signingDate != null) {
				/*
				 * RFC 3852 [4] states that "dates between January 1, 1950 and
				 * December 31, 2049 (inclusive) MUST be encoded as UTCTime. Any
				 * dates with year values before 1950 or after 2049 MUST be encoded
				 * as GeneralizedTime".
				 */
				if (signingDate.compareTo(JANUARY_1950) >= 0 && signingDate.before(JANUARY_2050)
						&& !(attrValue.toASN1Primitive() instanceof ASN1UTCTime)) { // must be ASN1UTCTime
					LOG.warn("RFC 3852 states that dates between January 1, 1950 and December 31, 2049 (inclusive) " +
							"MUST be encoded as UTCTime. Any dates with year values before 1950 or after 2049 " +
							"MUST be encoded as GeneralizedTime. Date found is {} encoded as {}",
							signingDate, attrValue.getClass());
					return null;
				}
				return signingDate;
			}
			LOG.warn("Error when reading signing time. Unrecognized {}", attrValue.getClass());
		}
		return null;
	}

	/**
	 * Finds archive {@link TimeStampToken}s
	 *
	 * @param unsignedAttributes {@link AttributeTable} to obtain timestamps from
	 * @return a list of {@link TimeStampToken}s
	 */
	public static List<TimeStampToken> findArchiveTimeStampTokens(AttributeTable unsignedAttributes) {
		List<TimeStampToken> timeStamps = new ArrayList<>();
		Attribute[] attributes = unsignedAttributes.toASN1Structure().getAttributes();
		for (final Attribute attribute : attributes) {
			if (isArchiveTimeStampToken(attribute)) {
				TimeStampToken timeStampToken = CAdESUtils.getTimeStampToken(attribute);
				if (timeStampToken != null) {
					timeStamps.add(timeStampToken);
				}
			}
		}
		return timeStamps;
	}

	/**
	 * Returns a list of all CMS timestamp identifiers
	 *
	 * @return a list of {@link ASN1ObjectIdentifier}s
	 */
	public static List<ASN1ObjectIdentifier> getTimestampOids() {
		return timestampOids;
	}

	/**
	 * Checks if the attribute is of an allowed archive timestamp type
	 *
	 * @param attribute {@link Attribute} to check
	 * @return true if the attribute represents an archive timestamp element, false
	 *         otherwise
	 */
	public static boolean isArchiveTimeStampToken(Attribute attribute) {
		ASN1ObjectIdentifier attrOid = attribute.getAttrType();
		if (attrOid != null) {
			return TimestampType.ARCHIVE_TIMESTAMP == getTimestampTypeByOid(attrOid);
		}
		return false;
	}

	/**
	 * This method returns a corresponding TimestampType for the given CMS {@code oid}
	 *
	 * @param oid {@link ASN1ObjectIdentifier} of the timestamp attribute
	 * @return {@link TimestampType}, null when OID is not recognized
	 */
	public static TimestampType getTimestampTypeByOid(ASN1ObjectIdentifier oid) {
		if (id_aa_ets_contentTimestamp.equals(oid)) {
			return TimestampType.CONTENT_TIMESTAMP;
		} else if (id_aa_signatureTimeStampToken.equals(oid)) {
			return TimestampType.SIGNATURE_TIMESTAMP;
		} else if (id_aa_ets_certCRLTimestamp.equals(oid)) {
			return TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP;
		} else if (id_aa_ets_escTimeStamp.equals(oid)) {
			return TimestampType.VALIDATION_DATA_TIMESTAMP;
		} else if (id_aa_ets_archiveTimestampV2.equals(oid) || id_aa_ets_archiveTimestampV3.equals(oid)) {
			return TimestampType.ARCHIVE_TIMESTAMP;
		}
		return null;
	}

	/**
	 * Returns ats-hash-index table, with a related version present in from timestamp's unsigned properties
	 *
	 * @param timestampUnsignedAttributes {@link AttributeTable} unsigned properties of the timestamp
	 * @return the content of SignedAttribute: ATS-hash-index unsigned attribute with a present version
	 */
	public static ASN1Sequence getAtsHashIndex(AttributeTable timestampUnsignedAttributes) {
		ASN1ObjectIdentifier atsHashIndexVersionIdentifier = getAtsHashIndexVersionIdentifier(timestampUnsignedAttributes);
		return getAtsHashIndexByVersion(timestampUnsignedAttributes, atsHashIndexVersionIdentifier);
	}

	/**
	 * Extract the Unsigned Attribute Archive Timestamp Cert Hash Index from a timestampToken
	 *
	 * @param atsHashIndexValue {@link ASN1Sequence}
	 * @return {@link ASN1Sequence}
	 */
	public static ASN1Sequence getCertificatesHashIndex(final ASN1Sequence atsHashIndexValue) {
		if (atsHashIndexValue != null) {
			int certificateIndex = 0;
			if (atsHashIndexValue.size() > 3) {
				certificateIndex++;
			}
			return (ASN1Sequence) atsHashIndexValue.getObjectAt(certificateIndex).toASN1Primitive();
		}
		return null;
	}

	/**
	 * Extract the Unsigned Attribute Archive Timestamp Crl Hash Index from a timestampToken
	 *
	 * @param atsHashIndexValue {@link ASN1Sequence}
	 * @return {@link ASN1Sequence}
	 */
	public static ASN1Sequence getCRLHashIndex(final ASN1Sequence atsHashIndexValue) {
		if (atsHashIndexValue != null) {
			int crlIndex = 1;
			if (atsHashIndexValue.size() > 3) {
				crlIndex++;
			}
			return (ASN1Sequence) atsHashIndexValue.getObjectAt(crlIndex).toASN1Primitive();
		}
		return null;
	}

	/**
	 * Extract the Unsigned Attribute Archive Timestamp Attribute Hash Index from a timestampToken
	 *
	 * @param atsHashIndexValue {@link ASN1Sequence}
	 * @return {@link ASN1Sequence}
	 */
	public static ASN1Sequence getUnsignedAttributesHashIndex(final ASN1Sequence atsHashIndexValue) {
		if (atsHashIndexValue != null) {
			int unsignedAttributesIndex = 2;
			if (atsHashIndexValue.size() > 3) {
				unsignedAttributesIndex++;
			}
			return (ASN1Sequence) atsHashIndexValue.getObjectAt(unsignedAttributesIndex).toASN1Primitive();
		}
		return null;
	}

	/**
	 * Returns ats-hash-index table, with a specified version present in from timestamp's unsigned properties
	 *
	 * @param timestampUnsignedAttributes {@link AttributeTable} unsigned properties of the timestamp
	 * @param atsHashIndexVersionIdentifier {@link ASN1ObjectIdentifier} identifier of ats-hash-index table to get
	 * @return the content of SignedAttribute: ATS-hash-index unsigned attribute with a requested version if present
	 */
	public static ASN1Sequence getAtsHashIndexByVersion(AttributeTable timestampUnsignedAttributes,
														ASN1ObjectIdentifier atsHashIndexVersionIdentifier) {
		if (timestampUnsignedAttributes != null && atsHashIndexVersionIdentifier != null) {
			final Attribute[] attributes = DSSASN1Utils.getAsn1Attributes(timestampUnsignedAttributes, atsHashIndexVersionIdentifier);
			if (Utils.arraySize(attributes) == 1) {
				final Attribute atsHashIndexAttribute = attributes[0];
				ASN1Encodable attrValue = DSSASN1Utils.getAsn1Encodable(atsHashIndexAttribute);
				if (attrValue != null) {
					return (ASN1Sequence) attrValue.toASN1Primitive();
				}
			}
		}
		return null;
	}

	/**
	 * Returns {@code ASN1ObjectIdentifier} of the found AtsHashIndex
	 * @param timestampUnsignedAttributes {@link AttributeTable} of the timestamp's unsignedAttributes
	 * @return {@link ASN1ObjectIdentifier} of the AtsHashIndex element version
	 */
	public static ASN1ObjectIdentifier getAtsHashIndexVersionIdentifier(AttributeTable timestampUnsignedAttributes) {
		if (timestampUnsignedAttributes != null) {
			Attributes attributes = timestampUnsignedAttributes.toASN1Structure();
			for (Attribute attribute : attributes.getAttributes()) {
				ASN1ObjectIdentifier attrType = attribute.getAttrType();
				if (id_aa_ATSHashIndex.equals(attrType) || id_aa_ATSHashIndexV2.equals(attrType) || id_aa_ATSHashIndexV3.equals(attrType)) {
					LOG.debug("Unsigned attribute of type [{}] found in the timestamp.", attrType);
					return attrType;
				}
			}
			LOG.warn("The timestamp unsignedAttributes does not contain ATSHashIndex!");
		}
		return null;
	}

	/**
	 * Returns octets from the given attribute by defined atsh-hash-index type
	 *
	 * @param attribute                     {@link Attribute} to get byte array from
	 * @param atsHashIndexVersionIdentifier {@link ASN1ObjectIdentifier} to specify
	 *                                      rules
	 * @return byte array
	 */
	public static List<byte[]> getOctetStringForAtsHashIndex(Attribute attribute, ASN1ObjectIdentifier atsHashIndexVersionIdentifier) {
		/*
		 *  id_aa_ATSHashIndexV3 (EN 319 122-1 v1.1.1) -> Each one shall contain the hash
		 *  value of the octets resulting from concatenating the Attribute.attrType field and one of the instances of
		 *  AttributeValue within the Attribute.attrValues within the unsignedAttrs field. One concatenation
		 *  operation shall be performed as indicated above, and the hash value of the obtained result included in
		 *  unsignedAttrsHashIndex
		 */
		if (id_aa_ATSHashIndexV3.equals(atsHashIndexVersionIdentifier)) {
			return getATSHashIndexV3OctetString(attribute.getAttrType(), attribute.getAttrValues());
		} else {
			/*
			 * id_aa_ATSHashIndex (TS 101 733 v2.2.1) and id_aa_ATSHashIndexV2 (EN 319 122-1 v1.0.0) ->
			 * The field unsignedAttrsHashIndex shall be a sequence of octet strings. Each one shall contain the hash value of
			 * one instance of Attribute within the unsignedAttrs field of the SignerInfo.
			 */
			return Collections.singletonList(DSSASN1Utils.getDEREncoded(attribute));
		}
	}

	/**
	 * Returns octets from the given attribute for ATS-Hash-Index-v3 table
	 *
	 * @param attributeIdentifier {@link ASN1ObjectIdentifier} of the corresponding
	 *                            Attribute
	 * @param attributeValues     {@link ASN1Set} of the corresponding Attribute
	 * @return byte array representing an octet string
	 */
	public static List<byte[]> getATSHashIndexV3OctetString(ASN1ObjectIdentifier attributeIdentifier,
															ASN1Set attributeValues) {
		List<byte[]> octets = new ArrayList<>();
		byte[] attrType = DSSASN1Utils.getDEREncoded(attributeIdentifier);
		for (ASN1Encodable asn1Encodable : attributeValues.toArray()) {
			octets.add(Utils.concat(attrType, DSSASN1Utils.getDEREncoded(asn1Encodable)));
		}
		return octets;
	}

	/**
	 * Returns a list of all CMS evidence record identifiers
	 *
	 * @return a list of {@link ASN1ObjectIdentifier}s
	 */
	public static List<ASN1ObjectIdentifier> getEvidenceRecordOids() {
		return evidenceRecordOids;
	}

	/**
	 * Gets the evidence record incorporation type based on the {@code unsignedAttributeOID}
	 *
	 * @param unsignedAttributeOID {@link ASN1ObjectIdentifier}
	 * @return {@link EvidenceRecordIncorporationType}
	 */
	public static EvidenceRecordIncorporationType getEvidenceRecordIncorporationType(ASN1ObjectIdentifier unsignedAttributeOID) {
		if (id_aa_er_internal.equals(unsignedAttributeOID)) {
			return EvidenceRecordIncorporationType.INTERNAL_EVIDENCE_RECORD;
		} else if (id_aa_er_external.equals(unsignedAttributeOID)) {
			return EvidenceRecordIncorporationType.EXTERNAL_EVIDENCE_RECORD;
		}
		throw new UnsupportedOperationException(String.format("The unsigned attribute with OID '%s' is not supported " +
				"for the evidence record incorporation!", unsignedAttributeOID.getId()));
	}

	/**
	 * Gets a generation time of the evidence record as indicated by the first timestamp's generation time
	 *
	 * @param evidenceRecord {@link org.bouncycastle.asn1.tsp.EvidenceRecord} to get a generation time for
	 * @return {@link Date} generation time
	 */
	public static Date getEvidenceRecordGenerationTime(org.bouncycastle.asn1.tsp.EvidenceRecord evidenceRecord) {
		if (evidenceRecord != null) {
			ArchiveTimeStampSequence archiveTimeStampSequence = evidenceRecord.getArchiveTimeStampSequence();
			if (archiveTimeStampSequence != null) {
				ArchiveTimeStampChain[] archiveTimeStampChains = archiveTimeStampSequence.getArchiveTimeStampChains();
				if (Utils.isArrayNotEmpty(archiveTimeStampChains)) {
					ArchiveTimeStamp[] archiveTimestamps = archiveTimeStampChains[0].getArchiveTimestamps();
					if (Utils.isArrayNotEmpty(archiveTimestamps)) {
						ContentInfo contentInfo = archiveTimestamps[0].getTimeStamp();
						TimeStampToken timeStampToken = toTimeStampToken(contentInfo);
						if (timeStampToken != null) {
							return timeStampToken.getTimeStampInfo().getGenTime();
						}
					}
				}
			}
		}
		return null;
	}

	private static TimeStampToken toTimeStampToken(ContentInfo contentInfo) {
		if (contentInfo != null) {
            try {
                return new TimeStampToken(contentInfo);
            } catch (TSPException | IOException e) {
                throw new DSSException(String.format("Unable to build a timestamp token : %s", e.getMessage()), e);
            }
        }
		return null;
	}

	/**
	 * Checks if the {@code attributeTable} is empty
	 *
	 * @param attributeTable {@link AttributeTable}
	 * @return TRUE if the attribute table is empty, FALSE otherwise
	 */
	public static boolean isEmpty(AttributeTable attributeTable) {
		return (attributeTable == null) || (attributeTable.size() == 0);
	}

	/**
	 * Returns the current {@code originalAttributeTable} if instantiated, an empty {@code AttributeTable} if null
	 *
	 * @param originalAttributeTable {@link AttributeTable}
	 * @return {@link AttributeTable}
	 */
	public static AttributeTable emptyIfNull(AttributeTable originalAttributeTable) {
		if (originalAttributeTable != null) {
			return originalAttributeTable;
		}
		return new AttributeTable(new Hashtable<ASN1ObjectIdentifier, Attribute>());
	}

	/**
	 * Checks if the given attribute is an instance of the expected asn1ObjectIdentifier type
	 *
	 * @param attribute {@link Attribute} to check
	 * @param asn1ObjectIdentifier {@link ASN1ObjectIdentifier} type to check against
	 * @return TRUE if the attribute is of type asn1ObjectIdentifier, FALSE otherwise
	 */
	public static boolean isAttributeOfType(Attribute attribute, ASN1ObjectIdentifier asn1ObjectIdentifier) {
		if (attribute == null) {
			return false;
		}
		ASN1ObjectIdentifier objectIdentifier = attribute.getAttrType();
		return asn1ObjectIdentifier.equals(objectIdentifier);
	}

	/**
	 * Creates a TimeStampToken from the provided {@code attribute}
	 *
	 * @param attribute {@link Attribute} to generate {@link TimeStampToken} from
	 * @return {@link TimeStampToken}
	 */
	public static TimeStampToken getTimeStampToken(Attribute attribute) {
		try {
			CMSSignedData signedData = getCMSSignedData(attribute);
			if (signedData != null) {
				return new TimeStampToken(signedData);
			}
		} catch (IOException | CMSException | TSPException e) {
			LOG.warn("The given TimeStampToken cannot be created! Reason: [{}]", e.getMessage(), e);
		}
		return null;
	}

	/**
	 * Creates a CMSSignedData from the provided {@code attribute}
	 *
	 * @param attribute {@link Attribute} to generate {@link CMSSignedData} from
	 * @return {@link CMSSignedData}
	 * @throws IOException in case of encoding exception
	 * @throws CMSException in case if the provided {@code attribute} cannot be converted to {@link CMSSignedData}
	 */
	public static CMSSignedData getCMSSignedData(Attribute attribute) throws CMSException, IOException {
		ASN1Encodable value = DSSASN1Utils.getAsn1Encodable(attribute);
		if (value instanceof DEROctetString) {
			LOG.warn("Illegal content for CMSSignedData (OID : {}) : OCTET STRING is not allowed !", attribute.getAttrType());
		} else {
			ASN1Primitive asn1Primitive = value.toASN1Primitive();
			return new CMSSignedData(asn1Primitive.getEncoded());
		}
		return null;
	}

	/**
	 * Gets encoded value of the {@code Attribute}
	 *
	 * @param attribute {@link Attribute} to get encoded binaries for
	 * @return byte array
	 * @throws IOException if an exception on data reading occurs
	 */
	public static byte[] getEncodedValue(Attribute attribute) throws IOException {
		ASN1Encodable value = getAsn1Encodable(attribute);
		ASN1Primitive asn1Primitive = value.toASN1Primitive();
		return asn1Primitive.getEncoded();
	}

	/**
	 * Gets the SignedData.encapContentInfo.eContentType identifier value
	 *
	 * @param cmsSignedData {@link CMSSignedData}
	 * @return {@link ASN1ObjectIdentifier} cmsSignedData.getSignedContentTypeOID()
	 * @deprecated since DSS 6.3. To be removed.
	 */
	@Deprecated
	public static ASN1ObjectIdentifier getEncapsulatedContentType(final CMSSignedData cmsSignedData) {
		final ContentInfo contentInfo = cmsSignedData.toASN1Structure();
		final SignedData signedData = SignedData.getInstance(contentInfo.getContent());
		return signedData.getEncapContentInfo().getContentType();
	}

	/**
	 * This method returns encoded binaries used for OCSP token incorporation within a SignedData.crls attribute
	 *
	 * @param binaries byte array containing OCSP token
	 * @param objectIdentifier {@link ASN1ObjectIdentifier}
	 * @return encoded binaries
	 */
	public static byte[] getSignedDataEncodedOCSPResponse(byte[] binaries, ASN1ObjectIdentifier objectIdentifier) {
		// Compute DERTaggedObject with the same algorithm how it was created
		// See: org.bouncycastle.cms.CMSUtils getOthersFromStore()
		OtherRevocationInfoFormat otherRevocationInfoFormat = new OtherRevocationInfoFormat(
				objectIdentifier, DSSASN1Utils.toASN1Primitive(binaries));
		// false value specifies an implicit encoding method
		DERTaggedObject derTaggedObject = new DERTaggedObject(false, 1, otherRevocationInfoFormat);
		return DSSASN1Utils.getDEREncoded(derTaggedObject);
	}

	/**
	 * Returns {@code ASN1Encodable} of the {@code attribute}
	 *
	 * @param attribute {@link Attribute}
	 * @return {@link ASN1Encodable}
	 * @deprecated since DSS 6.3. See {@code DSSASN1Utils#getAsn1Encodable(Attribute)}
	 */
	@Deprecated
	public static ASN1Encodable getAsn1Encodable(Attribute attribute) {
		return attribute.getAttrValues().getObjectAt(0);
	}

}
