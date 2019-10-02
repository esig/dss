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

import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signingCertificate;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signingCertificateV2;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

public final class CMSUtils {

	private static final Logger LOG = LoggerFactory.getLogger(CMSUtils.class);
	
	public static final DigestAlgorithm DEFAULT_ARCHIVE_TIMESTAMP_HASH_ALGO = DigestAlgorithm.SHA256;

	private CMSUtils() {
	}

	/**
	 * This method generate {@code CMSSignedData} using the provided #{@code CMSSignedDataGenerator}, the content and
	 * the indication if the content should be encapsulated.
	 *
	 * @param generator
	 * @param content
	 * @param encapsulate
	 * @return
	 */
	public static CMSSignedData generateCMSSignedData(final CMSSignedDataGenerator generator, final CMSTypedData content, final boolean encapsulate) {
		try {
			return generator.generate(content, encapsulate);
		} catch (CMSException e) {
			throw new DSSException(e);
		}
	}

	public static CMSSignedData generateDetachedCMSSignedData(final CMSSignedDataGenerator generator, final CMSProcessableByteArray content)
			throws DSSException {
		return generateCMSSignedData(generator, content, false);
	}

	/**
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
			throw new DSSException(e);
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

		Attribute attribute = null;
		if (digestAlgorithm == DigestAlgorithm.SHA1) {
			final ESSCertID essCertID = new ESSCertID(certHash, issuerSerial);
			SigningCertificate signingCertificate = new SigningCertificate(essCertID);
			attribute = new Attribute(id_aa_signingCertificate, new DERSet(signingCertificate));
		} else {
			ESSCertIDv2 essCertIdv2 = null;
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
	 * Returns a new {@code AttributeTable} with replaced {@code attributeToReplace} by {@code attributeToAdd} 
	 * 
	 * @param attributeTable {@link AttributeTable} to replace value in
	 * @param attributeToReplace {@link CMSSignedData} to be replaced
	 * @param attributeToAdd {@link CMSSignedData} to replace by
	 * @return a new {@link AttributeTable}
	 * @throws IOException in case of encoding error
	 * @throws CMSException in case of CMSException
	 */
	public static AttributeTable replaceAttribute(AttributeTable attributeTable, 
			CMSSignedData attributeToReplace, CMSSignedData attributeToAdd) throws IOException, CMSException {
		ASN1EncodableVector newAsn1EncodableVector = new ASN1EncodableVector();
		ASN1EncodableVector oldAsn1EncodableVector = attributeTable.toASN1EncodableVector();
		for (int ii = 0; ii < oldAsn1EncodableVector.size(); ii++) {
			Attribute attribute = (Attribute) oldAsn1EncodableVector.get(ii);
			if (equals(DSSASN1Utils.getCMSSignedData(attribute), attributeToReplace)) {
				ASN1Primitive asn1Primitive = DSSASN1Utils.toASN1Primitive(attributeToAdd.getEncoded());
				newAsn1EncodableVector.add(new Attribute(attribute.getAttrType(), new DERSet(asn1Primitive)));
			} else {
				newAsn1EncodableVector.add(attribute);
			}
		}
		return new AttributeTable(newAsn1EncodableVector);		
	}
	
	private static boolean equals(CMSSignedData signedData, CMSSignedData signedDataToCompare) throws IOException {
		if (Arrays.equals(signedData.getEncoded(), signedDataToCompare.getEncoded())) {
			return true;
		}
		return false;
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
	 * @param cmsSignedData {@link CMSSignedData} to get original document from
	 * @return original {@link DSSDocument}
	 */
	public static DSSDocument getOriginalDocument(CMSSignedData cmsSignedData, List<DSSDocument> detachedDocuments) {
		CMSTypedData signedContent = null;
		if (cmsSignedData != null) {
			signedContent = cmsSignedData.getSignedContent();
		}
		if (signedContent != null && !(signedContent instanceof CMSAbsentContent)) {
			return new InMemoryDocument(CMSUtils.getSignedContent(signedContent));
		} else if (Utils.collectionSize(detachedDocuments) == 1) {
			return detachedDocuments.get(0);
		} else {
			throw new DSSException("Only enveloping and detached signatures are supported");
		}
	}
	
	public static CMSTypedData getContentToBeSign(final DSSDocument toSignData) {
		CMSTypedData content = null;
		if (toSignData instanceof DigestDocument) {
			content = new CMSAbsentContent();
		} else {
			content = new CMSProcessableByteArray(DSSUtils.toByteArray(toSignData));
		}
		return content;
	}

}
