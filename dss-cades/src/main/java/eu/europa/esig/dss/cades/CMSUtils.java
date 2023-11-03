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
package eu.europa.esig.dss.cades;

import eu.europa.esig.dss.cades.signature.CustomMessageDigestCalculatorProvider;
import eu.europa.esig.dss.cades.validation.PrecomputedDigestCalculatorProvider;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signingCertificate;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signingCertificateV2;

/**
 * The utils for dealing with CMS object
 */
public final class CMSUtils {

	private static final Logger LOG = LoggerFactory.getLogger(CMSUtils.class);

	/** The default DigestAlgorithm for ArchiveTimestamp */
	public static final DigestAlgorithm DEFAULT_ARCHIVE_TIMESTAMP_HASH_ALGO = DigestAlgorithm.SHA256;

	/** 01-01-1950 date, see RFC 3852 (month param is zero-based (i.e. 0 for January)) */
	private static final Date JANUARY_1950 = DSSUtils.getUtcDate(1950, 0, 1);

	/** 01-01-2050 date, see RFC 3852 (month param is zero-based (i.e. 0 for January)) */
	private static final Date JANUARY_2050 = DSSUtils.getUtcDate(2050, 0, 1);

	/**
	 * Utils class
	 */
	private CMSUtils() {
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
	 */
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
	 */
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
	 */
	public static CMSSignedData generateDetachedCMSSignedData(final CMSSignedDataGenerator generator,
															  final CMSProcessableByteArray content) {
		return generateCMSSignedData(generator, content, false);
	}

	/**
	 * This method is used to ensure the presence of all items from SignedData.digestAlgorithm set
	 * from {@code oldCmsSignedData} within {@code newCmsSignedData}
	 *
	 * @param newCmsSignedData {@link CMSSignedData} to be extended with digest algorithms, if required
 	 * @param oldCmsSignedData {@link CMSSignedData} to copy digest algorithms set from
	 * @return extended {@link CMSSignedData}
	 */
	public static CMSSignedData populateDigestAlgorithmSet(CMSSignedData newCmsSignedData,
														   CMSSignedData oldCmsSignedData) {
		if (oldCmsSignedData != null) {
			for (AlgorithmIdentifier algorithmIdentifier : oldCmsSignedData.getDigestAlgorithmIDs()) {
				newCmsSignedData = addDigestAlgorithm(newCmsSignedData, algorithmIdentifier);
			}
		}
		return newCmsSignedData;
	}

	/**
	 * This method adds a DigestAlgorithm used by an Archive TimeStamp to
	 * the SignedData.digestAlgorithms set, when required.
	 *
	 * See ETSI EN 319 122-1, ch. "5.5.3 The archive-time-stamp-v3 attribute"
	 *
	 * @param cmsSignedData {@link CMSSignedData} to extend
	 * @param algorithmIdentifier {@link AlgorithmIdentifier} to add
	 * @return {@link CMSSignedData}
	 */
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
	 */
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
		return DSSASN1Utils.emptyIfNull(unsignedAttributes);
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
		return DSSASN1Utils.emptyIfNull(signedAttributes);
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
	 *            The signing certificate to be append
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
	 * Returns a signed attribute with the given {@code oid} from {@code signerInformation} if present
	 *
	 * @param signerInformation {@link SignerInformation} containing signed attributes
	 * @param oid {@link ASN1ObjectIdentifier} oid of the element to extract
	 * @return {@link Attribute} with the given OID
	 */
	public static Attribute getSignedAttribute(final SignerInformation signerInformation, ASN1ObjectIdentifier oid) {
		final AttributeTable signedAttributes = signerInformation.getSignedAttributes();
		if (signedAttributes == null) {
			return null;
		}
		return signedAttributes.get(oid);
	}

	/**
	 * Returns an unsigned attribute by its given {@code oid}
	 * @param signerInformation {@link SignerInformation} to get attribute from
	 * @param oid {@link ASN1ObjectIdentifier} of the target attribute
	 * @return {@link Attribute}
	 */
	public static Attribute getUnsignedAttribute(SignerInformation signerInformation, ASN1ObjectIdentifier oid) {
		final AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
		if (unsignedAttributes == null) {
			return null;
		}
		return unsignedAttributes.get(oid);
	}

	/**
	 * Checks if the signature is detached
	 * @param cmsSignedData {@link CMSSignedData}
	 * @return TRUE if the signature is detached, FALSE otherwise
	 */
	public static boolean isDetachedSignature(CMSSignedData cmsSignedData) {
		return cmsSignedData.isDetachedSignature();
	}
	
	/**
	 * Returns the original document from the provided {@code cmsSignedData}
	 *
	 * @param cmsSignedData {@link CMSSignedData} to get original document from
	 * @param detachedDocuments list of {@link DSSDocument}s
	 * @return original {@link DSSDocument}
	 */
	public static DSSDocument getOriginalDocument(CMSSignedData cmsSignedData, List<DSSDocument> detachedDocuments) {
		CMSTypedData signedContent = null;
		if (cmsSignedData != null) {
			signedContent = cmsSignedData.getSignedContent();
		}
		if (signedContent != null && !isDetachedSignature(cmsSignedData)) {
			return new InMemoryDocument(CMSUtils.getSignedContent(signedContent));
		} else if (Utils.collectionSize(detachedDocuments) == 1) {
			return detachedDocuments.get(0);
		} else {
			throw new DSSException("Only enveloping and detached signatures are supported");
		}
	}

	/**
	 * Returns the content to be signed
	 *
	 * @param toSignData {@link DSSDocument} to sign
	 * @return {@link CMSTypedData}
	 */
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
			return new CustomMessageDigestCalculatorProvider(digestAlgorithm, toSignDocument.getDigest(digestAlgorithm));
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
			if (DSSASN1Utils.isAttributeOfType(attribute, OID.id_aa_ets_archiveTimestampV2)) {
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

}
