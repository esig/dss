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
package eu.europa.esig.dss.cades.validation.timestamp;

import eu.europa.esig.dss.cades.CAdESUtils;
import eu.europa.esig.dss.cades.signature.CadesLevelBaselineLTATimestampExtractor;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSUtils;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSMessageDigestCalculator;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.timestamp.TimestampMessageDigestBuilder;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import java.util.Objects;

import static eu.europa.esig.dss.spi.OID.id_aa_ets_archiveTimestampV2;
import static eu.europa.esig.dss.spi.OID.id_aa_ets_archiveTimestampV3;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certificateRefs;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_revocationRefs;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;

/**
 * Builds timestamped data binaries for a CAdES signature
 *
 */
public class CAdESTimestampMessageDigestBuilder implements TimestampMessageDigestBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESTimestampMessageDigestBuilder.class);

	/** The error message to be thrown in case of a message-imprint build error */
	private static final String MESSAGE_IMPRINT_ERROR = "Unable to compute message-imprint for TimestampToken with Id '{}'. Reason : {}";

	/** The CMS */
	private final CMS cms;

	/** The SignerInformation of the related signature */
	private final SignerInformation signerInformation;

	/** The list of detached documents */
	private final List<DSSDocument> detachedDocuments;

	/** The instance of CadesLevelBaselineLTATimestampExtractor */
	private final CadesLevelBaselineLTATimestampExtractor timestampExtractor;

	/** The digest algorithm to be used for message-imprint digest computation */
	private DigestAlgorithm digestAlgorithm;

	/** Timestamp token to compute message-digest for */
	private TimestampToken timestampToken;

	/**
	 * The constructor to compute message-imprint for timestamps related to the {@code signature},
	 * to be used on timestamp creation.
	 *
	 * @param signature {@link CAdESSignature} to create timestamps for
	 * @param digestAlgorithm {@link DigestAlgorithm} to be used for message-imprint digest computation
	 */
	public CAdESTimestampMessageDigestBuilder(final CAdESSignature signature,
											  final DigestAlgorithm digestAlgorithm) {
		this(signature, signature.getCertificateSource().getSignedDataCertificates());
		Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm cannot be null!");
		this.digestAlgorithm = digestAlgorithm;
	}

	/**
	 * The constructor to compute message-imprint for timestamps related to the {@code signature},
	 * to be used on timestamp creation.
	 *
	 * @param signature {@link CAdESSignature} to create timestamps for
	 * @param certificateSource {@link ListCertificateSource} merged certificate source of the signature
	 * @param digestAlgorithm {@link DigestAlgorithm} to be used for message-imprint digest computation
	 * @deprecated since DSS 6.2. Please use instead constructor
	 * 			   {@code new CAdESTimestampMessageDigestBuilder(CAdESSignature signature, DigestAlgorithm digestAlgorithm}
	 */
	@Deprecated
	public CAdESTimestampMessageDigestBuilder(final CAdESSignature signature,
											  final ListCertificateSource certificateSource,
											  final DigestAlgorithm digestAlgorithm) {
		this(signature, certificateSource.getCertificates());
		Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm cannot be null!");
		this.digestAlgorithm = digestAlgorithm;
	}

	/**
	 * The constructor to compute message-imprint for timestamps related to the {@code signature}.
	 * This constructor uses a provides {@code certificateSource} to validate the ats-v3-hash-table
	 *
	 * @param signature {@link CAdESSignature} containing timestamps
	 * @param certificateSource {@link ListCertificateSource} merged certificate source of the signature
	 * @param timestampToken {@link TimestampToken} to compute message-digest for
	 */
	public CAdESTimestampMessageDigestBuilder(final CAdESSignature signature,
											  final ListCertificateSource certificateSource,
											  final TimestampToken timestampToken) {
		this(signature, certificateSource.getCertificates());
		Objects.requireNonNull(timestampToken, "TimestampToken cannot be null!");
		this.timestampToken = timestampToken;
		this.digestAlgorithm = timestampToken.getDigestAlgorithm();
	}

	/**
	 * The default constructor
	 *
	 * @param signature {@link CAdESSignature} containing timestamps
	 * @param certificates a list of {@link CertificateToken}s to extract info for ats-v3-hash-table
	 */
	private CAdESTimestampMessageDigestBuilder(final CAdESSignature signature,
											   final List<CertificateToken> certificates) {
		Objects.requireNonNull(signature, "Signature cannot be null!");
		Objects.requireNonNull(certificates, "List of CertificateToken's cannot be null!");
		this.cms = signature.getCMS();
		this.signerInformation = signature.getSignerInformation();
		this.detachedDocuments = signature.getDetachedContents();
		this.timestampExtractor = new CadesLevelBaselineLTATimestampExtractor(signature);
	}

	@Override
	public DSSMessageDigest getContentTimestampMessageDigest() {
		return getOriginalDocumentDigest();
	}

	@Override
	public DSSMessageDigest getSignatureTimestampMessageDigest() {
		byte[] signature = signerInformation.getSignature();
		return new DSSMessageDigest(digestAlgorithm, DSSUtils.digest(digestAlgorithm, signature));
	}

	@Override
	public DSSMessageDigest getTimestampX1MessageDigest() {
		try {
			final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);

			digestCalculator.update(signerInformation.getSignature());
			// We don't include the outer SEQUENCE, only the attrType and
			// attrValues as stated by the TS Â§6.3.5, NOTE 2

			final Attribute[] attributes = CAdESUtils.getUnsignedAttributes(signerInformation, id_aa_signatureTimeStampToken);
			if (Utils.isArrayNotEmpty(attributes)) {
				for (Attribute attribute : attributes) {
					digestCalculator.update(DSSASN1Utils.getDEREncoded(attribute.getAttrType()));
					digestCalculator.update(DSSASN1Utils.getDEREncoded(attribute.getAttrValues()));
				}
			}
			// Method is common to Type 1 and Type 2
			writeTimestampX2MessageDigest(digestCalculator);
			return digestCalculator.getMessageDigest(digestAlgorithm);

		} catch (Exception e) {
			if (LOG.isDebugEnabled()) {
				LOG.warn(MESSAGE_IMPRINT_ERROR, timestampToken.getDSSIdAsString(), e.getMessage(), e);
			} else {
				LOG.warn(MESSAGE_IMPRINT_ERROR, timestampToken.getDSSIdAsString(), e.getMessage());
			}
		}
		return null;
	}

	@Override
	public DSSMessageDigest getTimestampX2MessageDigest() {
		try {
			final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);
			writeTimestampX2MessageDigest(digestCalculator);
			return digestCalculator.getMessageDigest(digestAlgorithm);

		} catch (Exception e) {
			if (LOG.isDebugEnabled()) {
				LOG.warn(MESSAGE_IMPRINT_ERROR, timestampToken.getDSSIdAsString(), e.getMessage(), e);
			} else {
				LOG.warn(MESSAGE_IMPRINT_ERROR, timestampToken.getDSSIdAsString(), e.getMessage());
			}
		}
		return null;
	}

	private void writeTimestampX2MessageDigest(DSSMessageDigestCalculator digestCalculator) {
		// Those are common to Type 1 and Type 2
		final Attribute[] certAttributes = CAdESUtils.getUnsignedAttributes(signerInformation, id_aa_ets_certificateRefs);
		if (Utils.isArrayNotEmpty(certAttributes)) {
			for (Attribute attribute : certAttributes) {
				digestCalculator.update(DSSASN1Utils.getDEREncoded(attribute.getAttrType()));
				digestCalculator.update(DSSASN1Utils.getDEREncoded(attribute.getAttrValues()));
			}
		}
		final Attribute[] revAttributes = CAdESUtils.getUnsignedAttributes(signerInformation, id_aa_ets_revocationRefs);
		if (Utils.isArrayNotEmpty(revAttributes)) {
			for (Attribute attribute : revAttributes) {
				digestCalculator.update(DSSASN1Utils.getDEREncoded(attribute.getAttrType()));
				digestCalculator.update(DSSASN1Utils.getDEREncoded(attribute.getAttrValues()));
			}
		}
	}

	@Override
	public DSSMessageDigest getArchiveTimestampMessageDigest() {
		// V3 is used by default
		final ArchiveTimestampType archiveTimestampType = timestampToken != null ?
				timestampToken.getArchiveTimestampType() : ArchiveTimestampType.CAdES_V3;

		DSSMessageDigest messageDigest;
		switch (archiveTimestampType) {
		case CAdES_V2:
			/*
			 * There is a difference between message imprint calculation in ETSI TS 101 733 version 1.8.3 and version 2.2.1.
			 * So we first check the message imprint according to 2.2.1 version and then if it fails get the message imprint
			 * data for the 1.8.3 version message imprint calculation. 
			 */
			messageDigest = getArchiveTimestampDataV2( true);
			if (!timestampToken.matchData(messageDigest, true)) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("Unable to match message imprint for an Archive TimestampToken V2 with Id '{}' "
							+ "by including unsigned attribute tags and length, try to compute the data without...", timestampToken.getDSSIdAsString());
				}
				messageDigest = getArchiveTimestampDataV2(false);
			}
			break;
		case CAdES_V3:
			messageDigest = getArchiveTimestampDataV3();
			break;
		default:
			throw new DSSException("Unsupported ArchiveTimestampType " + archiveTimestampType);
		}

		return messageDigest;
	}

	private DSSMessageDigest getArchiveTimestampDataV3() throws DSSException {
		final Attribute atsHashIndexAttribute = timestampExtractor.getVerifiedAtsHashIndex(signerInformation, timestampToken);
		final DSSDocument originalDocument = getOriginalDocument();
		if (originalDocument != null) {
			return timestampExtractor.getArchiveTimestampV3MessageImprint(
					signerInformation, atsHashIndexAttribute, originalDocument, digestAlgorithm);
		} else {
			LOG.warn("The original document is not found for TimestampToken with Id '{}'! "
					+ "Unable to compute message imprint.", timestampToken.getDSSIdAsString());
			return DSSMessageDigest.createEmptyDigest();
		}
	}
	
	private DSSMessageDigest getOriginalDocumentDigest() {
		DSSDocument originalDocument = getOriginalDocument();
		if (originalDocument != null) {
			final byte[] digest = originalDocument.getDigestValue(digestAlgorithm);
			return new DSSMessageDigest(digestAlgorithm, digest);
		} else {
			LOG.warn("The original document is not found for TimestampToken with Id '{}'! "
					+ "Unable to compute message imprint.", timestampToken.getDSSIdAsString());
			return DSSMessageDigest.createEmptyDigest();
		}
	}
	
	/**
	 * There is a difference in ETSI TS 101 733 version 1.8.3 and version 2.2.1 in archive-timestamp-v2 hash calculation.
	 * In the 1.8.3 version the calculation did not include the tag and the length octets of the unsigned attributes set.
	 * The hash calculation is described in Annex K in both versions of ETSI TS 101 733.
	 * The differences are in TableK.3: Signed Data in rows 22 and 23.
	 * However, there is a note in 2.2.1 version (Annex K, Table K.3: SignedData, Note 3) that says:
	 * "A previous version of CAdES did not include the tag and length octets of this SET OF type
	 * of unsignedAttrs element in this annex, which contradicted the normative section. To maximize
	 * interoperability, it is recommended to simultaneously compute the two hash values
	 * (including and not including the tag and length octets of SET OF type) and to test
	 * the value of the timestamp against both."
	 * The includeUnsignedAttrsTagAndLength parameter decides whether the tag and length octets are included.
	 * <p>
	 * According to RFC 5652 it is possible to use DER or BER encoding for SignedData structure.
	 * The exception is the signed attributes attribute and authenticated attributes which
	 * have to be DER encoded. 
	 *
	 * @param includeUnsignedAttrsTagAndLength decides whether the tag and length octets are included.
	 * @return {@link DSSMessageDigest} archiveTimestampDataV2 message-imprint digest
	 */
	private DSSMessageDigest getArchiveTimestampDataV2(boolean includeUnsignedAttrsTagAndLength) throws DSSException {
		try {
			final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);

			try (OutputStream nullOS = Utils.nullOutputStream();
				 OutputStream dos = digestCalculator.getOutputStream(nullOS)) {

				writeContentInfoBytes(dos);

				if (cms.isDetachedSignature()) {
					writeOriginalDocumentBinaries(dos);
				}

				writeCertificateDataBytes(dos);

				writeCRLDataBytes(dos);

				writeSignerInfoBytes(dos, includeUnsignedAttrsTagAndLength);

				return digestCalculator.getMessageDigest(digestAlgorithm);

			}

		} catch (Exception e) {
			// When error in computing or in format the algorithm just continues.
			String errorMessage = "An error in computing of message-imprint for a TimestampToken with Id : %s. Reason : %s";
			if (LOG.isDebugEnabled()) {
				LOG.warn(String.format(errorMessage, timestampToken.getDSSIdAsString(), e.getMessage()), e);
			} else {
				LOG.warn(String.format(errorMessage, timestampToken.getDSSIdAsString(), e.getMessage()));
			}
			return DSSMessageDigest.createEmptyDigest();
		}
	}
	
	private void writeContentInfoBytes(OutputStream os) throws IOException {
		CMSUtils.writeContentInfoEncoded(cms, os);
	}
	
	private void writeOriginalDocumentBinaries(OutputStream os) throws IOException {
		/*
		 * Detached signatures have either no encapContentInfo in signedData, or it
		 * exists but has no eContent
		 */
		DSSDocument originalDocument = getOriginalDocument();
		if (originalDocument != null) {
			os.write(DSSUtils.toByteArray(originalDocument));
		} else {
			throw new DSSException(String.format("The detached content is not provided for a TimestampToken with Id '%s'. "
					+ "Not possible to compute message imprint!", timestampToken.getDSSIdAsString()));
		}
	}
	
	private void writeCertificateDataBytes(OutputStream os) throws IOException {
		CMSUtils.writeSignedDataCertificatesEncoded(cms, os);
	}
	
	private void writeCRLDataBytes(OutputStream os) throws IOException {
		CMSUtils.writeSignedDataCRLsEncoded(cms, os);
	}
	
	private void writeSignerInfoBytes(final OutputStream os, boolean includeUnsignedAttrsTagAndLength) throws IOException {
		final SignerInfo signerInfo = signerInformation.toASN1Structure();
		final ASN1Set unauthenticatedAttributes = signerInfo.getUnauthenticatedAttributes();
		final ASN1Sequence filteredUnauthenticatedAttributes = filterUnauthenticatedAttributes(unauthenticatedAttributes, timestampToken);
		final ASN1Sequence asn1Object = getSignerInfoEncoded(signerInfo, filteredUnauthenticatedAttributes, includeUnsignedAttrsTagAndLength);
		for (int ii = 0; ii < asn1Object.size(); ii++) {
			final byte[] signerInfoBytes = DSSASN1Utils.getDEREncoded(asn1Object.getObjectAt(ii).toASN1Primitive());
			if (LOG.isTraceEnabled()) {
				LOG.trace("SignerInfoBytes: {}", DSSUtils.toHex(signerInfoBytes));
			}
			os.write(signerInfoBytes);
		}
	}

	/**
	 * Remove any archive-timestamp-v2/3 attribute added after the
	 * timestampToken
	 */
	private ASN1Sequence filterUnauthenticatedAttributes(ASN1Set unauthenticatedAttributes, TimestampToken timestampToken) {
		ASN1EncodableVector result = new ASN1EncodableVector();
		for (int ii = 0; ii < unauthenticatedAttributes.size(); ii++) {

			final Attribute attribute = Attribute.getInstance(unauthenticatedAttributes.getObjectAt(ii));
			final ASN1ObjectIdentifier attrType = attribute.getAttrType();
			if (id_aa_ets_archiveTimestampV2.equals(attrType) || id_aa_ets_archiveTimestampV3.equals(attrType)) {
				try {

					TimeStampToken token = CAdESUtils.getTimeStampToken(attribute);
					if (token == null || !token.getTimeStampInfo().getGenTime().before(timestampToken.getGenerationTime())) {
						continue;
					}

				} catch (Exception e) {
					throw new DSSException(String.format("Unexpected error occurred on reading unsigned properties : %s",
							e.getMessage()), e);
				}
			}
			result.add(unauthenticatedAttributes.getObjectAt(ii));
		}
		return new DERSequence(result);
	}

	/**
	 * Copied from org.bouncycastle.asn1.cms.SignerInfo#toASN1Object() and
	 * adapted to be able to use the custom unauthenticatedAttributes
	 * <p>
	 * There is a difference in ETSI TS 101 733 version 1.8.3 and version 2.2.1 in archive-timestamp-v2 hash calculation.
	 * In the 1.8.3 version the calculation did not include the tag and the length octets of the unsigned attributes set.
	 * The hash calculation is described in Annex K in both versions of ETSI TS 101 733.
	 * The differences are in TableK.3: Signed Data in rows 22 and 23.
	 * However, there is a note in 2.2.1 version (Annex K, Table K.3: SignedData, Note 3) that says:
	 * "A previous version of CAdES did not include the tag and length octets of this SET OF type
	 * of unsignedAttrs element in this annex, which contradicted the normative section. To maximize
	 * interoperability, it is recommended to imultaneously compute the two hash values
	 * (including and not including the tag and length octets of SET OF type) and to test
	 * the value of the timestamp against both."
	 * The includeUnsignedAttrsTagAndLength parameter decides whether the tag and length octets are included.
	 *
	 * @param signerInfo {@link SignerInfo}
	 * @param unauthenticatedAttributes {@link ASN1Sequence}
	 * @param includeUnsignedAttrsTagAndLength decides whether the tag and length octets are included
	 * @return {@link ASN1Sequence}
	 */
	private ASN1Sequence getSignerInfoEncoded(final SignerInfo signerInfo, final ASN1Sequence unauthenticatedAttributes,
											  final boolean includeUnsignedAttrsTagAndLength) {

		ASN1EncodableVector v = new ASN1EncodableVector();

		v.add(signerInfo.getVersion());
		v.add(signerInfo.getSID());
		v.add(signerInfo.getDigestAlgorithm());

		final DERTaggedObject signedAttributes = CAdESUtils.getDERSignedAttributes(signerInformation);
		if (signedAttributes != null) {
			v.add(signedAttributes);
		}

		v.add(signerInfo.getDigestEncryptionAlgorithm());
		v.add(signerInfo.getEncryptedDigest());

		if (unauthenticatedAttributes != null) {
			if (includeUnsignedAttrsTagAndLength) {
				v.add(new DERTaggedObject(false, 1, unauthenticatedAttributes));
			} else {
				for (int i = 0; i < unauthenticatedAttributes.size(); i++) {
					v.add(unauthenticatedAttributes.getObjectAt(i));
				}
			}
		}
		
		return new DERSequence(v);
	}
	
	private DSSDocument getOriginalDocument() {
		try {
			return CAdESUtils.getOriginalDocument(cms, detachedDocuments);
		} catch (DSSException e) {
			LOG.warn("Cannot extract original document! Reason : {}", e.getMessage());
			return null;
		}
	}

}
