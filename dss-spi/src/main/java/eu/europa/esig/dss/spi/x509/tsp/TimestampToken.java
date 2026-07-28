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
package eu.europa.esig.dss.spi.x509.tsp;

import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.EvidenceRecordTimestampType;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureValidity;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.model.identifier.TokenIdentifier;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.security.DSSSignerInformationVerifierSecurityFactory;
import eu.europa.esig.dss.spi.x509.CandidatesForSigningCertificate;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.SignerIdentifier;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * SignedToken containing a TimeStamp.
 *
 */
@SuppressWarnings("serial")
public class TimestampToken extends Token {

	private static final Logger LOG = LoggerFactory.getLogger(TimestampToken.class);

	/**
	 * BouncyCastle representation of a TimeStamp Token
	 */
	private final TimeStampToken timeStamp;

	/**
	 * Type of the timestamp relatively to the signature
	 */
	private final TimestampType timeStampType;

	/**
	 * Certificate source extracted from the timestamp
	 */
	private final TimestampCertificateSource certificateSource;

	/**
	 * CRL source extracted from the timestamp
	 */
	private final TimestampCRLSource crlSource;

	/**
	 * OCSP source extracted from the timestamp
	 */
	private final TimestampOCSPSource ocspSource;

	/**
	 * List of references to tokens covered (protected) by the timestamp
	 */
	private final List<TimestampedReference> timestampedReferences;

	/**
	 * Builds a time-stamp token unique identifier
	 */
	private TimestampIdentifierBuilder identifierBuilder;

	/**
	 * Internal variables defining whether the timestamp has been validated
	 */
	private boolean processed = false;

	/**
	 * Computed message-imprint
	 */
	private Digest messageImprint;

	/**
	 * Defines whether the message-imprint has been found
	 */
	private boolean messageImprintData;

	/**
	 * Defines whether the computed message-imprint is intact
	 */
	private Boolean messageImprintIntact = null;
	
	/**
	 * In case of a detached timestamp
	 */
	private String filename;
	
	/**
	 * Only present for detached timestamps;
	 */
	private List<SignatureScope> timestampScopes;

	/**
	 * The timestamped manifest file, when applicable (ASiC with CAdES)
	 */
	private ManifestFile manifestFile;

	/**
	 * In case of XAdES IndividualDataObjectsTimeStamp, Includes shall be specified
	 */
	private List<TimestampInclude> timestampIncludes;

	/**
	 * In case of an Evidence record time-stamp, contains references to
	 */
	private List<ReferenceValidation> referenceValidations;

	/**
	 * Returns a list of detached evidence records covering the time-stamp, when applicable
	 */
	private List<EvidenceRecord> detachedEvidenceRecords;

	/**
	 * Defines for archive timestamp its type.
	 */
	private ArchiveTimestampType archiveTimestampType;

	/**
	 * Defines for an evidence record archive timestamp its type.
	 */
	private EvidenceRecordTimestampType evidenceRecordTimestampType;

	/**
	 * This attribute is used for XAdES timestamps. It indicates the canonicalization method
	 * used for message-imprint computation.
	 * <p>
	 * NOTE: Used for XAdES/JAdES only
	 */
	private String canonicalizationMethod;

	/**
	 * Identifies a TSA issued the timestamp token
	 * <p>
	 * NOTE: Takes a value only for a successfully validated token
	 */
	private X500Principal tsaX500Principal;

	/**
	 * Cached list of signing certificate candidates
	 */
	private CandidatesForSigningCertificate candidatesForSigningCertificate;

	/**
	 * Contains validation status of the ats-hash-index(-v3) attribute.
	 * NOTE: applicable only for CMS archive-time-stamp-v3 timestamps.
	 */
	private ArchiveTimestampHashIndexStatus hashIndexStatus;

	/**
	 * Default constructor
	 *
	 * @param binaries byte array
	 * @param type {@link TimestampType}
	 * @throws TSPException if timestamp creation exception occurs
	 * @throws IOException if IOException occurs
	 * @throws CMSException if CMS data building exception occurs
	 */
	public TimestampToken(final byte[] binaries, final TimestampType type) throws TSPException, IOException, CMSException {
		this(binaries, type, new ArrayList<>());
	}

	/**
	 * Default constructor with timestamped references
	 *
	 * @param binaries byte array
	 * @param type {@link TimestampType}
	 * @param timestampedReferences a list of {@link TimestampedReference}s
	 * @throws TSPException if timestamp creation exception occurs
	 * @throws IOException if IOException occurs
	 * @throws CMSException if CMS data building exception occurs
	 */
	public TimestampToken(final byte[] binaries, final TimestampType type, final List<TimestampedReference> timestampedReferences) throws TSPException, IOException, CMSException {
		this(new CMSSignedData(binaries), type, timestampedReferences);
	}

	/**
	 * Default constructor with timestamped references and identifier builder
	 *
	 * @param binaries byte array
	 * @param type {@link TimestampType}
	 * @param timestampedReferences a list of {@link TimestampedReference}s
	 * @param identifierBuilder {@link TimestampIdentifierBuilder}
	 * @throws TSPException if timestamp creation exception occurs
	 * @throws IOException if IOException occurs
	 * @throws CMSException if CMS data building exception occurs
	 */
	public TimestampToken(final byte[] binaries, final TimestampType type, final List<TimestampedReference> timestampedReferences,
						  final TimestampIdentifierBuilder identifierBuilder) throws TSPException, IOException, CMSException {
		this(new CMSSignedData(binaries), type, timestampedReferences, identifierBuilder);
	}

	/**
	 * Constructor from CMS with timestamped references
	 *
	 * @param cms {@link CMSSignedData}
	 * @param type {@link TimestampType}
	 * @param timestampedReferences a list of {@link TimestampedReference}s
	 * @throws TSPException if timestamp creation exception occurs
	 * @throws IOException if IOException occurs
	 */
	public TimestampToken(final CMSSignedData cms, final TimestampType type, final List<TimestampedReference> timestampedReferences) throws TSPException, IOException {
		this(new TimeStampToken(cms), type, timestampedReferences);
	}

	/**
	 * Constructor from CMS with timestamped references and identifier builder
	 *
	 * @param cms {@link CMSSignedData}
	 * @param type {@link TimestampType}
	 * @param timestampedReferences a list of {@link TimestampedReference}s
	 * @param identifierBuilder {@link TimestampIdentifierBuilder}
	 * @throws TSPException if timestamp creation exception occurs
	 * @throws IOException if IOException occurs
	 */
	public TimestampToken(final CMSSignedData cms, final TimestampType type, final List<TimestampedReference> timestampedReferences,
						  final TimestampIdentifierBuilder identifierBuilder) throws TSPException, IOException {
		this(new TimeStampToken(cms), type, timestampedReferences, identifierBuilder);
	}

	/**
	 * Constructor with an indication of the timestamp type and time-stamped references.
	 * The default constructor for {@code TimestampToken}. Builds an implementation independent identifier.
	 *
	 * @param timeStamp
	 *                              {@code TimeStampToken}
	 * @param type
	 *                              {@code TimestampType}
	 * @param timestampedReferences
	 *                              timestamped references
	 *                              timestamp comes from
	 */
	public TimestampToken(final TimeStampToken timeStamp, final TimestampType type, final List<TimestampedReference> timestampedReferences) {
		this(timeStamp, type, timestampedReferences, null);
	}

	/**
	 * Constructor with an indication of the timestamp type, time-stamped references and an identifier builder.
	 *
	 * @param timeStamp
	 *                              {@code TimeStampToken}
	 * @param type
	 *                              {@code TimestampType}
	 * @param timestampedReferences
	 *                              timestamped references
	 *                              timestamp comes from
	 * @param identifierBuilder
	 *                              {@link TimestampIdentifierBuilder}
	 */
	public TimestampToken(final TimeStampToken timeStamp, final TimestampType type, final List<TimestampedReference> timestampedReferences,
						  final TimestampIdentifierBuilder identifierBuilder) {
		this.timeStamp = timeStamp;
		this.timeStampType = type;
		this.certificateSource = new TimestampCertificateSource(timeStamp);
		this.ocspSource = new TimestampOCSPSource(timeStamp);
		this.crlSource = new TimestampCRLSource(timeStamp);
		this.timestampedReferences = timestampedReferences;
		this.identifierBuilder = identifierBuilder;
	}

	@Override
	public X500Principal getIssuerX500Principal() {
		return tsaX500Principal;
	}

	@Override
	public String getAbbreviation() {
		return timeStampType.name() + ": " + getDSSIdAsString() + ": " + DSSUtils.formatDateToRFC(timeStamp.getTimeStampInfo().getGenTime());
	}
	
	/**
	 * Returns {@code TimestampCertificateSource} for the timestamp
	 * 
	 * @return {@link TimestampCertificateSource}
	 */
	public TimestampCertificateSource getCertificateSource() {
		return certificateSource;
	}
	
	/**
	 * Returns {@code TimestampCRLSource} for the timestamp
	 * 
	 * @return {@link TimestampCRLSource}
	 */
	public TimestampCRLSource getCRLSource() {
		return crlSource;
	}

	/**
	 * Returns {@code TimestampOCSPSource} for the timestamp
	 * 
	 * @return {@link TimestampOCSPSource}
	 */
	public TimestampOCSPSource getOCSPSource() {
		return ocspSource;
	}

	/**
	 * Indicated if the signature is intact and the message-imprint matches the computed message-imprint.
	 * <p>
	 * NOTE: The method isSignedBy(CertificateToken) must be called before calling the method.
	 *       See {@code TimestampToken.isSignatureIntact()} for more details
	 *
	 * @return TRUE if the signature is cryptographically intact and message-imprint matches, FALSE otherwise
	 */
	@Override
	public boolean isValid() {
		return isSignatureIntact() && isMessageImprintDataFound() && isMessageImprintDataIntact() && areReferenceValidationsValid();
	}

	/**
	 * Checks if the timestamp token is signed by the given publicKey
	 * 
	 * @param certificateToken
	 *              the candidate to be tested
	 * @return true if this token is signed by the given public key
	 */
	@Override
	public synchronized boolean isSignedBy(final CertificateToken certificateToken) {
		if (publicKeyOfTheSigner != null) {
			return publicKeyOfTheSigner.equals(certificateToken.getPublicKey());
		} else if (SignatureValidity.VALID == checkIsSignedBy(certificateToken)) {
			if (!isSelfSigned()) {
				this.publicKeyOfTheSigner = certificateToken.getPublicKey();
			}
			return true;
		}
		return false;
	}
	
	@Override
	public synchronized boolean isSignedBy(final PublicKey publicKey) {
		throw new UnsupportedOperationException("Use method isSignedBy(certificateToken) for a TimestampToken validation!");
	}

	/**
	 * Checks if timestamp is signed by teh given certificate
	 *
	 * @param candidate {@link CertificateToken}
	 * @return {@link SignatureValidity}
	 */
	protected SignatureValidity checkIsSignedBy(final CertificateToken candidate) {

		final X509CertificateHolder x509CertificateHolder = DSSASN1Utils.getX509CertificateHolder(candidate);
		if (timeStamp.getSID().match(x509CertificateHolder)) {
			SignerInformationVerifier signerInformationVerifier = DSSSignerInformationVerifierSecurityFactory.CERTIFICATE_TOKEN_INSTANCE.build(candidate);

			// Try firstly to validate as a Timestamp and if that fails try to validate the
			// timestamp as a CMSSignedData
			if (isValidTimestamp(signerInformationVerifier) || isValidCMSSignedData(signerInformationVerifier)) {
				signatureValidity = SignatureValidity.VALID;
				this.tsaX500Principal = candidate.getSubject().getPrincipal();
				SignerInformation signerInformation = timeStamp.toCMSSignedData().getSignerInfos().get(timeStamp.getSID());

				if (EncryptionAlgorithm.RSASSA_PSS.getOid().equals(signerInformation.getEncryptionAlgOID())) {
					signatureAlgorithm = SignatureAlgorithm.forOidAndParams(signerInformation.getEncryptionAlgOID(),
							signerInformation.getEncryptionAlgParams());
				} else {
					EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.forName(candidate.getPublicKey().getAlgorithm());
					final AlgorithmIdentifier hashAlgorithm = signerInformation.getDigestAlgorithmID();
					final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(hashAlgorithm.getAlgorithm().getId());
					signatureAlgorithm = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digestAlgorithm);
				}
			} else {
				signatureValidity = SignatureValidity.INVALID;
			}

			return signatureValidity;
		}
		return SignatureValidity.INVALID;
	}

	private boolean isValidTimestamp(SignerInformationVerifier signerInformationVerifier) {
		try {
			// Validate the timestamp, the signing certificate,...
			timeStamp.validate(signerInformationVerifier);
			return true;
		} catch (TSPException e) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Unable to validate timestamp token : ", e);
			} else {
				LOG.warn("Unable to validate timestamp token : {}", e.getMessage());
			}
			signatureInvalidityReason = e.getClass().getSimpleName() + " : " + e.getMessage();
			return false;
		}
	}

	private boolean isValidCMSSignedData(SignerInformationVerifier signerInformationVerifier) {
		try {
			// Only validate the cryptographic validity
			SignerInformationStore signerInfos = timeStamp.toCMSSignedData().getSignerInfos();
			SignerInformation signerInformation = signerInfos.get(timeStamp.getSID());
			return signerInformation.verify(signerInformationVerifier);
		} catch (CMSException e) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Unable to validate the related CMSSignedData : ", e);
			} else {
				LOG.warn("Unable to validate the related CMSSignedData : {}", e.getMessage());
			}
			signatureInvalidityReason = e.getClass().getSimpleName() + " : " + e.getMessage();
			return false;
		}
	}
	
	@Override
	protected SignatureValidity checkIsSignedBy(final PublicKey publicKey) {
		throw new UnsupportedOperationException("Use method checkIsSignedBy(certificateToken) for a TimestampToken validation!");
	}

	/**
	 * Checks if the {@code TimeStampToken} matches the signed data.
	 *
	 * @param timestampedData
	 * 			  a {@code DSSDocument} representing the timestamped data
	 * @return true if the data is verified by the TimeStampToken
	 */
	public boolean matchData(final DSSDocument timestampedData) {
		return matchData(timestampedData, false);
	}
	
	/**
	 * Checks if the {@code TimeStampToken} matches the signed data.
	 * 
	 * @param timestampedData
	 * 			  a {@code DSSDocument} representing the timestamped data
	 * @param suppressMatchWarnings
	 * 			  if true the message imprint match warning logs are suppressed. 
	 * @return true if the data is verified by the TimeStampToken
	 */
	public boolean matchData(final DSSDocument timestampedData, final boolean suppressMatchWarnings) {
		processed = true;

		messageImprintData = timestampedData != null;
		messageImprintIntact = false;

		if (!messageImprintData) {
			LOG.warn("Timestamped data not found !");
			return false;
		}

		Digest currentMessageImprint = getMessageImprint();
		byte[] computedDigest = timestampedData.getDigestValue(currentMessageImprint.getAlgorithm());
		return matchData(computedDigest, suppressMatchWarnings);
	}

	/**
	 * Checks if the {@code TimeStampToken} matches the message-imprint digest with warning enabled.
	 *
	 * @param messageDigest
	 * 			  {@code DSSMessageDigest} representing the message-imprint digest
	 * @return true if the data is verified by the TimeStampToken
	 */
	public boolean matchData(final DSSMessageDigest messageDigest) {
		return matchData(messageDigest, false);
	}

	/**
	 * Checks if the {@code TimeStampToken} matches the message-imprint digest.
	 *
	 * @param messageDigest
	 * 			  {@code DSSMessageDigest} representing the message-imprint digest
	 * @param suppressMatchWarnings
	 * 			  if true the message imprint match warning logs are suppressed.
	 * @return true if the data is verified by the TimeStampToken
	 */
	public boolean matchData(final DSSMessageDigest messageDigest, final boolean suppressMatchWarnings) {
		processed = true;

		if (messageDigest == null || messageDigest.isEmpty()) {
			messageImprintIntact = false;
			if (!suppressMatchWarnings) {
				LOG.warn("Invalid or incomplete message-digest has been provided for timestamp verification!");
			}

		} else if (getDigestAlgorithm() != messageDigest.getAlgorithm()) {
			messageImprintIntact = false;
			if (!suppressMatchWarnings) {
				LOG.warn("DigestAlgorithm '{}' used in the provided message-digest does not match the one used " +
						"in the timestamp token '{}'!", messageDigest.getAlgorithm(), getDigestAlgorithm());
			}

		} else {
			messageImprintIntact = matchData(messageDigest.getValue(), suppressMatchWarnings);
		}
		return messageImprintIntact;
	}

	/**
	 * Checks if the {@code TimeStampToken} matches the signed data.
	 *
	 * @param expectedMessageImprintDigest
	 *                                    the expected message-imprint digest value
	 * @return true if the data is verified by the TimeStampToken
	 */
	public boolean matchData(final byte[] expectedMessageImprintDigest) {
		return matchData(expectedMessageImprintDigest, false);
	}

	/**
	 * Checks if the {@code TimeStampToken} matches the signed data.
	 *
	 * @param expectedMessageImprintDigest
	 *                                    the expected message-imprint digest value
	 * @param suppressMatchWarnings
	 *                                    if true the message imprint match warning
	 *                                    logs are suppressed.
	 * @return true if the data is verified by the TimeStampToken
	 */
	public boolean matchData(final byte[] expectedMessageImprintDigest, final boolean suppressMatchWarnings) {
		processed = true;

		messageImprintData = expectedMessageImprintDigest != null;
		messageImprintIntact = false;

		if (messageImprintData) {
			Digest currentMessageImprint = getMessageImprint();
			messageImprintIntact = Arrays.equals(expectedMessageImprintDigest, currentMessageImprint.getValue());
			if (!messageImprintIntact && !suppressMatchWarnings) {
				LOG.warn("Provided digest value for TimestampToken matchData : {}", Utils.toBase64(expectedMessageImprintDigest));
				LOG.warn("Digest ({}) present in TimestampToken : {}", currentMessageImprint.getAlgorithm(), Utils.toBase64(currentMessageImprint.getValue()));
				LOG.warn("Digest in TimestampToken matches digest of extracted data from document: {}", messageImprintIntact);
			}
		} else {
			LOG.warn("Timestamped data not found !");
		}

		return messageImprintIntact;
	}

	/**
	 * Checks if the timestamp's signature has been validated
	 *
	 * @return TRUE if the timestamp's signature has been validated, FALSE otherwise
	 */
	public boolean isProcessed() {
		return processed;
	}

	/**
	 * Retrieves the type of the timestamp token.
	 *
	 * @return {@code TimestampType}
	 */
	public TimestampType getTimeStampType() {
		return timeStampType;
	}

	/**
	 * Retrieves the timestamp generation time.
	 *
	 * @return {@code Date}
	 */
	public Date getGenerationTime() {
		return timeStamp.getTimeStampInfo().getGenTime();
	}

	@Override
	public Date getCreationDate() {
		return getGenerationTime();
	}

	/**
	 * This method returns the embedded message-imprint value
	 * 
	 * @return a Digest DTO with the algorithm and the value
	 */
	public Digest getMessageImprint() {
		if (messageImprint == null) {
			DigestAlgorithm messageImprintDigestAlgo = getDigestAlgorithm();
			byte[] messageImprintDigestValue = timeStamp.getTimeStampInfo().getMessageImprintDigest();
			messageImprint = new Digest(messageImprintDigestAlgo, messageImprintDigestValue);
		}
		return messageImprint;
	}

	/**
	 * This method returns a {@code DigestAlgorithm} used for message-imprint computation of the timestamp token
	 *
	 * @return {@link DigestAlgorithm}
	 */
	public DigestAlgorithm getDigestAlgorithm() {
		ASN1ObjectIdentifier oid = timeStamp.getTimeStampInfo().getMessageImprintAlgOID();
		return DigestAlgorithm.forOID(oid.getId());
	}

	/**
	 * Checks if the data for message-imprint computation has been found
	 *
	 * @return true if the message imprint data was found, false otherwise
	 */
	public boolean isMessageImprintDataFound() {
		return Utils.isTrue(messageImprintData);
	}

	/**
	 * The method {@code matchData} must be invoked previously.
	 *
	 * @return true if the message imprint data is intact, false otherwise
	 */
	public boolean isMessageImprintDataIntact() {
		if (!processed) {
			throw new IllegalStateException("Invoke matchData(byte[] data) method before!");
		}
		return Utils.isTrue(messageImprintIntact);
	}

	/**
	 * This method returns the file name of a detached timestamp
	 *
	 * @return {@link String}
	 */
	public String getFilename() {
		return filename;
	}

	/**
	 * Sets the filename of a detached timestamp
	 *
	 * @param filename
	 * 					{@link String}
	 */
	public void setFilename(String filename) {
		this.filename = filename;
	}

	/**
	 * This method returns the covered manifest file
	 * NOTE: applicable only for ASiC-E CAdES
	 * 
	 * @return {@link ManifestFile}
	 */
	public ManifestFile getManifestFile() {
		return manifestFile;
	}

	/**
	 * Sets the manifest file covered by the current timestamp
	 * NOTE: applicable only for ASiC-E CAdES
	 * 
	 * @param manifestFile 
	 * 					{@link ManifestFile}
	 */
	public void setManifestFile(ManifestFile manifestFile) {
		this.manifestFile = manifestFile;
	}

	/**
	 * Gets list of {@code TimestampedReference}s covered by the current timestamp
	 *
	 * @return {@code List} of {@code TimestampReference}s
	 */
	public List<TimestampedReference> getTimestampedReferences() {
		return timestampedReferences;
	}

	/**
	 * Gets the {@code ArchiveTimestampType}, when applicable
	 *
	 * @return {@code ArchiveTimestampType} in the case of an archive timestamp, {@code null} otherwise
	 */
	public ArchiveTimestampType getArchiveTimestampType() {
		return archiveTimestampType;
	}

	/**
	 * Archive timestamps can be of different subtype.
	 *
	 * @param archiveTimestampType
	 *            {@code ArchiveTimestampType}
	 */
	public void setArchiveTimestampType(final ArchiveTimestampType archiveTimestampType) {
		this.archiveTimestampType = archiveTimestampType;
	}

	/**
	 * Gets the {@code EvidenceRecordTimestampType}, when applicable
	 *
	 * @return {@code EvidenceRecordTimestampType} in the case of an evidence record archive time-stamp, null otherwise
	 */
	public EvidenceRecordTimestampType getEvidenceRecordTimestampType() {
		return evidenceRecordTimestampType;
	}

	/**
	 * Sets the {@code EvidenceRecordTimestampType}, for an evidence record's time-stamp
	 *
	 * @param evidenceRecordTimestampType {@link EvidenceRecordTimestampType}
	 */
	public void setEvidenceRecordTimestampType(EvidenceRecordTimestampType evidenceRecordTimestampType) {
		this.evidenceRecordTimestampType = evidenceRecordTimestampType;
	}

	/**
	 * Applies only from XAdES timestamps
	 *
	 * @return {@code String} representing the canonicalization method used by the timestamp
	 */
	public String getCanonicalizationMethod() {
		return canonicalizationMethod;
	}

	/**
	 * Allows to set the canonicalization method used by the timestamp. Applies only with XAdES timestamps.
	 *
	 * @param canonicalizationMethod
	 *            {@code String} representing the canonicalization method
	 */
	public void setCanonicalizationMethod(final String canonicalizationMethod) {
		this.canonicalizationMethod = canonicalizationMethod;
	}

	@Override
	public byte[] getEncoded() {
		return DSSASN1Utils.getDEREncoded(timeStamp);
	}

	/**
	 * Returns the covered references by the current timestamp (XAdES IndividualDataObjectsTimeStamp)
	 * 
	 * @return a list of timestamp's includes
	 */
	public List<TimestampInclude> getTimestampIncludes() {
		return timestampIncludes;
	}

	/**
	 * Sets the covered references by the current timestamp (XAdES IndividualDataObjectsTimeStamp)
	 *
	 * @param timestampIncludes a list of timestamp's includes
	 */
	public void setTimestampIncludes(List<TimestampInclude> timestampIncludes) {
		this.timestampIncludes = timestampIncludes;
	}

	/**
	 * Returns a list of timestamped data reference validations (used for Evidence Record timestamps)
	 *
	 * @return a list of {@link ReferenceValidation}s
	 */
	public List<ReferenceValidation> getReferenceValidations() {
		return referenceValidations;
	}

	/**
	 * Sets a list of timestamped data reference validations (used for Evidence Record timestamps)
	 *
	 * @param referenceValidations a list of {@link ReferenceValidation}s
	 */
	public void setReferenceValidations(List<ReferenceValidation> referenceValidations) {
		this.referenceValidations = referenceValidations;
	}

	/**
	 * This method verifies whether the corresponding reference validations are valid
	 *
	 * @return TRUE if all reference validations are valid, FALSE otherwise
	 */
	public boolean areReferenceValidationsValid() {
		if (Utils.isCollectionNotEmpty(referenceValidations)) {
			for (ReferenceValidation referenceValidation : referenceValidations) {
				if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE != referenceValidation.getType() &&
						(!referenceValidation.isFound() || !referenceValidation.isIntact())) {
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * Gets a list of detached evidence records covering the time-stamp, when applicable
	 *
	 * @return a list of {@link EvidenceRecord}s
	 */
	public List<EvidenceRecord> getDetachedEvidenceRecords() {
		if (detachedEvidenceRecords == null) {
			detachedEvidenceRecords = new ArrayList<>();
		}
		return detachedEvidenceRecords;
	}

	/**
	 * Adds an evidence record to the time-stamp's list
	 *
	 * @param evidenceRecord {@link EvidenceRecord}
	 */
	public void addDetachedEvidenceRecord(EvidenceRecord evidenceRecord) {
		getDetachedEvidenceRecords().add(evidenceRecord);
	}

	/**
	 * Returns the scope of the current timestamp (detached timestamps only)
	 * 
	 * @return a list of SignatureScope
	 */
	public List<SignatureScope> getTimestampScopes() {
		return timestampScopes;
	}

	/**
	 * Sets timestamp's signature scopes
	 *
	 * @param timestampScopes a list of {@link SignatureScope}s
	 */
	public void setTimestampScopes(List<SignatureScope> timestampScopes) {
		this.timestampScopes = timestampScopes;
	}

	/**
	 * Returns the list of wrapped certificates.
	 *
	 * @return {@code List} of {@code CertificateToken}
	 */
	public List<CertificateToken> getCertificates() {
		return certificateSource.getCertificates();
	}
	
	/**
	 * Returns the Set of contained certificate references.
	 *
	 * @return {@code Set} of {@code CertificateRef}
	 */
	public Set<CertificateRef> getCertificateRefs() {
		return certificateSource.getAllCertificateRefs();
	}

	/**
	 * Gets unsigned attribute table
	 *
	 * @return {@link AttributeTable}
	 */
	public AttributeTable getUnsignedAttributes() {
		return timeStamp.getUnsignedAttributes();
	}

	/**
	 * Returns a TSTInfo.tsa attribute identifying the timestamp issuer, when attribute is present
	 *
	 * @return {@link GeneralName}
	 */
	public X500Principal getTSTInfoTsa() {
		GeneralName tsaGeneralName = timeStamp.getTimeStampInfo().getTsa();
		if (tsaGeneralName != null) {
			try {
				X500Name x500Name = X500Name.getInstance(tsaGeneralName.getName());
				return DSSASN1Utils.toX500Principal(x500Name);
			} catch (Exception e) {
				LOG.warn("Unable to decode TSTInfo.tsa attribute value to X500Principal. Reason : {}", e.getMessage(), e);
			}
		}
		return null;
	}

	/**
	 * Gets BouncyCastle implementation of a TimestampToken
	 *
	 * @return {@link TimeStampToken}
	 */
	public TimeStampToken getTimeStamp() {
		return timeStamp;
	}

	@Override
	public String toString(String indentStr) {
		try {
			final StringBuilder out = new StringBuilder();
			out.append(indentStr).append("TimestampToken[signedBy=").append(getIssuerX500Principal());
			out.append(", generated: ").append(DSSUtils.formatDateToRFC(timeStamp.getTimeStampInfo().getGenTime()));
			out.append(" / ").append(timeStampType).append('\n');
			if (isSignatureIntact()) {

				indentStr += "\t";
				out.append(indentStr).append("Timestamp's signature validity: VALID").append('\n');
				indentStr = indentStr.substring(1);
			} else {

				if (!signatureInvalidityReason.isEmpty()) {

					indentStr += "\t";
					out.append(indentStr).append("Timestamp's signature validity: INVALID").append(" - ").append(signatureInvalidityReason).append('\n');
					indentStr = indentStr.substring(1);
				}
			}
			indentStr += "\t";
			if (messageImprintIntact != null) {
				if (Boolean.TRUE.equals(messageImprintIntact)) {
					out.append(indentStr).append("Timestamp MATCHES the signed data.").append('\n');
				} else {
					out.append(indentStr).append("Timestamp DOES NOT MATCH the signed data.").append('\n');
				}
			}
			out.append(']');
			return out.toString();
		} catch (Exception e) {
			return getClass().getName();
		}
	}
	
	/**
	 * Returns a set of found CertificateIdentifier in the SignerInformationStore
	 * 
	 * @return a set of {@link SignerIdentifier}s
	 */
	public Set<SignerIdentifier> getSignerInformationStoreInfos() {
		return getCertificateSource().getAllCertificateIdentifiers();
	}

	/**
	 * Returns an object with signing candidates
	 * 
	 * @return {@link CandidatesForSigningCertificate}
	 */
	public CandidatesForSigningCertificate getCandidatesForSigningCertificate() {
		if (candidatesForSigningCertificate == null) {
			candidatesForSigningCertificate = getCertificateSource()
					.getCandidatesForSigningCertificate(null);
		}
		return candidatesForSigningCertificate;
	}

	/**
	 * Returns used signer information from CMS Signed Data object
	 * 
	 * @return {@link SignerInformation}
	 */
	public SignerInformation getSignerInformation() {
		Collection<SignerInformation> signers = timeStamp.toCMSSignedData().getSignerInfos().getSigners(timeStamp.getSID());
		return signers.iterator().next();
	}

	/**
	 * Gets the validation status of the ats-hash-index(-v3) attribute, when applicable.
	 * NOTE: supports only archive-time-stamp-v3 timestamp type
	 *
	 * @return {@link ArchiveTimestampHashIndexStatus} if validation ts-hash-index(-v3) attribute has been performed,
	 *         NULL otherwise
	 */
	public ArchiveTimestampHashIndexStatus getAtsHashIndexStatus() {
		return hashIndexStatus;
	}

	/**
	 * Sets the validation status of the ats-hash-index(-v3) attribute, when applicable.
	 *
	 * @param hashIndexStatus {@link ArchiveTimestampHashIndexStatus}
	 */
	public void setAtsHashIndexStatus(ArchiveTimestampHashIndexStatus hashIndexStatus) {
		this.hashIndexStatus = hashIndexStatus;
	}

	@Override
	protected TokenIdentifier buildTokenIdentifier() {
		return getTimestampIdentifierBuilder().build();
	}

	/**
	 * Returns a {@code TimestampTokenIdentifierBuilder} implementation
	 *
	 * @return {@link TimestampIdentifierBuilder}
	 */
	protected TimestampIdentifierBuilder getTimestampIdentifierBuilder() {
		if (identifierBuilder == null) {
			identifierBuilder = new TimestampIdentifierBuilder(getEncoded()).setFilename(filename);
		}
		return identifierBuilder;
	}

	@Override
	public byte[] getDigest(DigestAlgorithm digestAlgorithm) {
		return DSSUtils.digest(digestAlgorithm, getEncoded());
	}

}
