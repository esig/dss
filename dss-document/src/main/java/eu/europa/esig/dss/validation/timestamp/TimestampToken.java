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
package eu.europa.esig.dss.validation.timestamp;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampLocation;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateRef;

/**
 * SignedToken containing a TimeStamp.
 *
 */
@SuppressWarnings("serial")
public class TimestampToken extends Token {

	private static final Logger LOG = LoggerFactory.getLogger(TimestampToken.class);

	private final TimeStampToken timeStamp;

	private final TimestampType timeStampType;

	private final TimestampCertificateSource certificateSource;
	
	private final TimestampCRLSource crlSource;
	
	private final TimestampOCSPSource ocspSource;

	private final List<TimestampedReference> timestampedReferences;

	private boolean processed = false;

	private boolean messageImprintData;

	private Boolean messageImprintIntact = null;
	
	private TimestampLocation timeStampLocation;

	/**
	 * In case of XAdES IndividualDataObjectsTimeStamp, Includes shall be specified
	 */
	private List<TimestampInclude> timestampIncludes;

	/**
	 * Defines for archive timestamp its type.
	 */
	private ArchiveTimestampType archiveTimestampType;

	/**
	 * This attribute is used for XAdES timestamps. It indicates the canonicalization method used before creating the
	 * digest.
	 */
	private String canonicalizationMethod;

	private X500Principal tsaX500Principal;

	/**
	 * This attribute is used only with XAdES timestamps. It represents the hash code of the DOM element containing the
	 * timestamp. It's an internal attribute which allows to
	 * unambiguously identify a timestamp.
	 */
	private int hashCode;
	
	public TimestampToken(final byte[] binaries, final TimestampType type) 
			throws TSPException, IOException, CMSException {
		this(binaries, type, new CertificatePool());
	}

	public TimestampToken(final byte[] binaries, final TimestampType type, final CertificatePool certPool) 
			throws TSPException, IOException, CMSException {
		this(binaries, type, certPool, null);
	}

	public TimestampToken(final byte[] binaries, final TimestampType type, final CertificatePool certPool, 
			final TimestampLocation timeStampLocation) throws TSPException, IOException, CMSException {
		this(binaries, type, certPool, new ArrayList<TimestampedReference>(), timeStampLocation);
	}

	public TimestampToken(final byte[] binaries, final TimestampType type, final CertificatePool certPool, 
			final List<TimestampedReference> timestampedReferences, final TimestampLocation timeStampLocation) throws TSPException, IOException, CMSException {
		this(new CMSSignedData(binaries), type, certPool, timestampedReferences, timeStampLocation);
	}

	public TimestampToken(final CMSSignedData cms, final TimestampType type, final CertificatePool certPool) 
			throws TSPException, IOException {
		this(cms, type, certPool, null);
	}

	public TimestampToken(final CMSSignedData cms, final TimestampType type, final CertificatePool certPool,
			final TimestampLocation timeStampLocation) throws TSPException, IOException {
		this(new TimeStampToken(cms), type, certPool, timeStampLocation);
	}

	public TimestampToken(final CMSSignedData cms, final TimestampType type, final CertificatePool certPool,
			final List<TimestampedReference> timestampedReferences, final TimestampLocation timeStampLocation) throws TSPException, IOException {
		this(new TimeStampToken(cms), type, certPool, timestampedReferences, timeStampLocation);
	}

	public TimestampToken(final TimeStampToken timeStamp, final TimestampType type) {
		this(timeStamp, type, new CertificatePool());
	}

	public TimestampToken(final TimeStampToken timeStamp, final TimestampType type, final CertificatePool certPool) {
		this(timeStamp, type, certPool, null);
	}

	public TimestampToken(final TimeStampToken timeStamp, final TimestampType type, final CertificatePool certPool,
			final TimestampLocation timeStampLocation) {
		this(timeStamp, type, certPool, new ArrayList<TimestampedReference>(), timeStampLocation);
	}

	/**
	 * Constructor with an indication of the timestamp type. The default constructor for {@code TimestampToken}.
	 *
	 * @param timeStamp
	 *            {@code TimeStampToken}
	 * @param type
	 *            {@code TimestampType}
	 * @param certPool
	 *            {@code CertificatePool} which is used to identify the signing certificate of the timestamp
	 * @param timeStampLocation
	 *            {@code TimestampLocation} defines where the timestamp comes from
	 */
	public TimestampToken(final TimeStampToken timeStamp, final TimestampType type, final CertificatePool certPool, 
			final List<TimestampedReference> timestampedReferences, final TimestampLocation timeStampLocation) {
		this(timeStamp, type, new TimestampCertificateSource(timeStamp, certPool), new TimestampCRLSource(timeStamp), 
				new TimestampOCSPSource(timeStamp), timestampedReferences, timeStampLocation);
	}

	/**
	 * Creates a new instance of {@link TimestampToken}
	 * @param timestampToken
	 *            {@code TimestampToken} to be cloned
	 */
	public TimestampToken(TimestampToken timestampToken) {
		this(timestampToken.timeStamp, timestampToken.timeStampType, timestampToken.certificateSource, 
				timestampToken.crlSource, timestampToken.ocspSource, new ArrayList<TimestampedReference>(timestampToken.timestampedReferences), 
				timestampToken.timeStampLocation);
	}
	
	TimestampToken(final TimeStampToken timeStamp, final TimestampType type, final TimestampCertificateSource certificateSource, 
			 final TimestampCRLSource crlSource, final TimestampOCSPSource ocspSource, final List<TimestampedReference> timestampedReferences,
			 final TimestampLocation timeStampLocation) {
		this.timeStamp = timeStamp;
		this.timeStampType = type;
		this.certificateSource = certificateSource;
		this.crlSource = crlSource;
		this.ocspSource = ocspSource;
		this.timestampedReferences = timestampedReferences;
		if (timeStampLocation != null) {
			this.timeStampLocation = timeStampLocation;
		}
	}

	@Override
	public X500Principal getIssuerX500Principal() {
		return tsaX500Principal;
	}

	@Override
	public String getAbbreviation() {
		return timeStampType.name() + ": " + getDSSIdAsString() + ": " + DSSUtils.formatInternal(timeStamp.getTimeStampInfo().getGenTime());
	}
	
	/**
	 * Returns {@code TimestampCRLSource} for the timestamp
	 * @return {@link TimestampCRLSource}
	 */
	public TimestampCRLSource getCRLSource() {
		return crlSource;
	}

	/**
	 * Returns {@code TimestampOCSPSource} for the timestamp
	 * @return {@link TimestampOCSPSource}
	 */
	public TimestampOCSPSource getOCSPSource() {
		return ocspSource;
	}
	
	@Override
	protected boolean checkIsSignedBy(final CertificateToken candidate) {

		final X509CertificateHolder x509CertificateHolder = DSSASN1Utils.getX509CertificateHolder(candidate);
		if (timeStamp.getSID().match(x509CertificateHolder)) {
			SignerInformationVerifier signerInformationVerifier = getSignerInformationVerifier(candidate);

			// Try firstly to validate as a Timestamp and if that fails try to validate the
			// timestamp as a CMSSignedData
			if (isValidTimestamp(signerInformationVerifier) || isValidCMSSignedData(signerInformationVerifier)) {
				signatureValid = true;
				this.tsaX500Principal = candidate.getSubjectX500Principal();
				SignerInformation signerInformation = timeStamp.toCMSSignedData().getSignerInfos()
						.get(timeStamp.getSID());
				
				if (SignatureAlgorithm.RSA_SSA_PSS_SHA1_MGF1.getOid().equals(signerInformation.getEncryptionAlgOID())) {
					signatureAlgorithm = SignatureAlgorithm.forOidAndParams(signerInformation.getEncryptionAlgOID(),
							signerInformation.getEncryptionAlgParams());
				} else {
					EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm
							.forName(candidate.getPublicKey().getAlgorithm());
					final AlgorithmIdentifier hashAlgorithm = timeStamp.getTimeStampInfo().getHashAlgorithm();
					final DigestAlgorithm digestAlgorithm = DigestAlgorithm
							.forOID(hashAlgorithm.getAlgorithm().getId());
					signatureAlgorithm = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digestAlgorithm);
				}
			} else {
				signatureValid = false;
			}

			return signatureValid;
		}
		return false;
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

	private SignerInformationVerifier getSignerInformationVerifier(final CertificateToken candidate) {
		try {
			final JcaSimpleSignerInfoVerifierBuilder verifier = new JcaSimpleSignerInfoVerifierBuilder();
			verifier.setProvider(DSSSecurityProvider.getSecurityProviderName());
			return verifier.build(candidate.getCertificate());
		} catch (OperatorException e) {
			throw new DSSException("Unable to build an instance of SignerInformationVerifier", e);
		}
	}

	/**
	 * Checks if the {@code TimeStampToken} matches the signed data.
	 *
	 * @param data
	 *            the array of {@code byte} representing the timestamped data
	 * @return true if the data is verified by the TimeStampToken
	 */
	public boolean matchData(final byte[] data) {
		return matchData(data, false);
	}
	
	/**
	 * Checks if the {@code TimeStampToken} matches the signed data.
	 * 
	 * This method is used when we want to test whether the {@code TimeStampToken} matches the signed data
	 * calculated according to ETSI TS 101 733 v2.2.1 and depending on the result re-run the message imprint
	 * calculation according to ETSI TS 101 733 v1.8.3. It is part of solution for the issue DSS-1401 
	 * (https://ec.europa.eu/cefdigital/tracker/browse/DSS-1401)
	 * 
	 * @param data
	 * 			  the array of {@code byte} representing the timestamped data
	 * @param suppressMatchWarnings
	 * 			  if true the message imprint match warning logs are suppressed. 
	 * @return true if the data is verified by the TimeStampToken
	 */
	public boolean matchData(final byte[] data, final boolean suppressMatchWarnings) {
		processed = true;

		messageImprintData = data != null;
		messageImprintIntact = false;

		if (messageImprintData) {
			try {
				final TimeStampTokenInfo timeStampInfo = timeStamp.getTimeStampInfo();
				final ASN1ObjectIdentifier hashAlgorithm = timeStampInfo.getHashAlgorithm().getAlgorithm();
				final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(hashAlgorithm.getId());

				final byte[] computedDigest = DSSUtils.digest(digestAlgorithm, data);
				final byte[] timestampDigest = timeStampInfo.getMessageImprintDigest();
				messageImprintIntact = Arrays.equals(computedDigest, timestampDigest);
				if (!messageImprintIntact && !suppressMatchWarnings) {
					LOG.warn("Computed digest ({}) on the extracted data from the document : {}", digestAlgorithm, Utils.toHex(computedDigest));
					LOG.warn("Digest present in TimestampToken: {}", Utils.toHex(timestampDigest));
					LOG.warn("Digest in TimestampToken matches digest of extracted data from document: {}", messageImprintIntact);
				}
			} catch (DSSException e) {
				LOG.warn("Unable to validate the timestamp", e);
			}
		} else {
			LOG.warn("Timestamped data not found !");
		}

		return messageImprintIntact;
	}

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
	 * Retrieves the location of timestamp token.
	 *
	 * @return {@code TimestampLocation}
	 */
	public TimestampLocation getTimestampLocation() {
		return timeStampLocation;
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
	 * Retrieves the {@code DigestAlgorithm} used to generate the digest value to
	 * timestamp.
	 *
	 * @return {@code DigestAlgorithm}
	 */
	public DigestAlgorithm getSignedDataDigestAlgo() {
		final ASN1ObjectIdentifier oid = timeStamp.getTimeStampInfo().getHashAlgorithm().getAlgorithm();
		return DigestAlgorithm.forOID(oid.getId());
	}

	/**
	 * Retrieves the message-imprint digest value.
	 *
	 * @return the byte array with the message-imprint digest value
	 */
	public byte[] getMessageImprintDigest() {
		return timeStamp.getTimeStampInfo().getMessageImprintDigest();
	}

	/**
	 * @return true if the message imprint data was found, false otherwise
	 */
	public Boolean isMessageImprintDataFound() {
		return messageImprintData;
	}

	/**
	 * The method {@code matchData} must be invoked previously.
	 *
	 * @return true if the message imprint data is intact, false otherwise
	 */
	public Boolean isMessageImprintDataIntact() {
		if (messageImprintIntact == null) {
			throw new DSSException("Invoke matchData(byte[] data) method before!");
		}
		return messageImprintIntact;
	}

	/**
	 * @return {@code List} of {@code TimestampReference}s
	 */
	public List<TimestampedReference> getTimestampedReferences() {
		return timestampedReferences;
	}

	/**
	 * @return {@code ArchiveTimestampType} in the case of an archive timestamp, {@code null} otherwise
	 */
	public ArchiveTimestampType getArchiveTimestampType() {
		return archiveTimestampType;
	}

	/**
	 * Archive timestamps can be of different sub type.
	 *
	 * @param archiveTimestampType
	 *            {@code ArchiveTimestampType}
	 */
	public void setArchiveTimestampType(final ArchiveTimestampType archiveTimestampType) {
		this.archiveTimestampType = archiveTimestampType;
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
	 * @return
	 */
	public List<TimestampInclude> getTimestampIncludes() {
		return timestampIncludes;
	}

	public void setTimestampIncludes(List<TimestampInclude> timestampIncludes) {
		this.timestampIncludes = timestampIncludes;
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
	 * Returns the list of contained certificate references.
	 *
	 * @return {@code List} of {@code CertificateRef}
	 */
	public List<CertificateRef> getCertificateRefs() {
		return certificateSource.getAllCertificateRefs();
	}

	public AttributeTable getUnsignedAttributes() {
		return timeStamp.getUnsignedAttributes();
	}

	/**
	 * Used only with XAdES timestamps.
	 *
	 * @param hashCode
	 *            the hash code of the DOM element containing the timestamp
	 */
	public void setHashCode(final int hashCode) {
		this.hashCode = hashCode;
	}

	/**
	 * Used only with XAdES timestamps.
	 *
	 * @return the hash code of the DOM element containing the timestamp
	 */
	public int getHashCode() {
		return hashCode;
	}

	@Override
	public String toString(String indentStr) {
		try {
			final StringBuilder out = new StringBuilder();
			out.append(indentStr).append("TimestampToken[signedBy=").append(getIssuerX500Principal());
			out.append(", generated: ").append(DSSUtils.formatInternal(timeStamp.getTimeStampInfo().getGenTime()));
			out.append(" / ").append(timeStampType).append('\n');
			if (signatureValid) {

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
				if (messageImprintIntact) {
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

	public SignerId getSignerId() {
		return timeStamp.getSID();
	}

	@Override
	public String getDSSIdAsString() {
		return "T-" + super.getDSSIdAsString();
	}

}
