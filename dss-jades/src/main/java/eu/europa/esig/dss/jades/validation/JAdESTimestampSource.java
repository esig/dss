package eu.europa.esig.dss.jades.validation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampLocation;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRL;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ListRevocationSource;
import eu.europa.esig.dss.validation.SignatureProperties;
import eu.europa.esig.dss.validation.timestamp.AbstractTimestampSource;
import eu.europa.esig.dss.validation.timestamp.TimestampDataBuilder;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;

public class JAdESTimestampSource extends AbstractTimestampSource<JAdESAttribute> {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESTimestampSource.class);

	private final JAdESSignature signature;

	public JAdESTimestampSource(JAdESSignature signature) {
		super(signature);

		this.signature = signature;
	}

	@Override
	protected SignatureProperties<JAdESAttribute> getSignedSignatureProperties() {
		return new JAdESSignedProperties(signature.getJws().getHeaders());
	}

	@Override
	@SuppressWarnings("unchecked")
	protected SignatureProperties<JAdESAttribute> getUnsignedSignatureProperties() {
		Map<String, Object> etsiU = new HashMap<>();
		Map<String, Object> unprotected = signature.getJws().getUnprotected();
		if (Utils.isMapNotEmpty(unprotected)) {
			etsiU = (Map<String, Object>) unprotected.get(JAdESHeaderParameterNames.ETSI_U);
		}
		return new JAdESUnsignedProperties(etsiU);
	}

	@Override
	protected boolean isContentTimestamp(JAdESAttribute signedAttribute) {
		return JAdESHeaderParameterNames.ADO_TST.equals(signedAttribute.getHeaderName());
	}

	/**
	 * Populates all the lists by data found into the signature
	 */
	@Override
	protected void makeTimestampTokens() {
		// initialize timestamp lists
		contentTimestamps = new ArrayList<>();
		signatureTimestamps = new ArrayList<>();
		archiveTimestamps = new ArrayList<>();
		sigAndRefsTimestamps = new ArrayList<>();
		refsOnlyTimestamps = new ArrayList<>();

		// initialize combined revocation sources
		crlSource = new ListRevocationSource<CRL>(signatureCRLSource);
		ocspSource = new ListRevocationSource<OCSP>(signatureOCSPSource);
		certificateSource = new ListCertificateSource(signatureCertificateSource);

		final SignatureProperties<JAdESAttribute> signedSignatureProperties = getSignedSignatureProperties();

		final List<JAdESAttribute> signedAttributes = signedSignatureProperties.getAttributes();
		for (JAdESAttribute signedAttribute : signedAttributes) {
			if (isContentTimestamp(signedAttribute)) {
				List<TimestampToken> currentTimestamps = extractTimestampTokens(signedAttribute,
						TimestampType.CONTENT_TIMESTAMP, getAllSignedDataReferences());

				if (Utils.isCollectionNotEmpty(currentTimestamps)) {
					contentTimestamps.addAll(currentTimestamps);
					for (TimestampToken contentTimestamp : currentTimestamps) {
						populateSources(contentTimestamp);
					}
				}
			} else {
				continue;
			}
		}

		final SignatureProperties<JAdESAttribute> unsignedSignatureProperties = getUnsignedSignatureProperties();
		if (!unsignedSignatureProperties.isExist()) {
			// timestamp tokens cannot be created if signature does not contain
			// "unsigned-signature-properties" element
			return;
		}

		final List<TimestampToken> timestamps = new ArrayList<>();
		// final List<TimestampedReference> encapsulatedReferences = new ArrayList<>();

		final List<JAdESAttribute> unsignedAttributes = unsignedSignatureProperties.getAttributes();
		for (JAdESAttribute unsignedAttribute : unsignedAttributes) {

			List<TimestampToken> currentTimestamps = null;

			if (isSignatureTimestamp(unsignedAttribute)) {

				currentTimestamps = extractTimestampTokens(unsignedAttribute, TimestampType.SIGNATURE_TIMESTAMP,
						getSignatureTimestampReferences());

				if (Utils.isCollectionNotEmpty(currentTimestamps)) {
					signatureTimestamps.addAll(currentTimestamps);
				}
			} else {
				LOG.warn("The unsigned attribute with name [{}] is not supported", unsignedAttribute);
				continue;
			}

			if (Utils.isCollectionNotEmpty(currentTimestamps)) {
				for (TimestampToken timestampToken : currentTimestamps) {
					populateSources(timestampToken);
					timestamps.add(timestampToken);
				}
			}
		}
	}

	@Override
	protected boolean isAllDataObjectsTimestamp(JAdESAttribute signedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isIndividualDataObjectsTimestamp(JAdESAttribute signedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isSignatureTimestamp(JAdESAttribute unsignedAttribute) {
		return JAdESHeaderParameterNames.SIG_TST.equals(unsignedAttribute.getHeaderName());
	}

	@Override
	protected boolean isCompleteCertificateRef(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isAttributeCertificateRef(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isCompleteRevocationRef(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isAttributeRevocationRef(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isRefsOnlyTimestamp(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isSigAndRefsTimestamp(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isCertificateValues(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isRevocationValues(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isArchiveTimestamp(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isTimeStampValidationData(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@SuppressWarnings("unchecked")
	private List<TimestampToken> extractTimestampTokens(JAdESAttribute signatureAttribute, TimestampType timestampType,
			List<TimestampedReference> references) {

		List<TimestampToken> result = new LinkedList<TimestampToken>();

		Map<String, Object> array = (Map<String, Object>) signatureAttribute.getValue();
		List<Map<String, Object>> tokens = (List<Map<String, Object>>) array.get(JAdESHeaderParameterNames.TST_TOKENS);

		for (Map<String, Object> jsonToken : tokens) {
			String tstBase64 = (String) jsonToken.get(JAdESHeaderParameterNames.VAL);
			try {
				result.add(new TimestampToken(Utils.fromBase64(tstBase64), timestampType, references,
						TimestampLocation.JAdES));
			} catch (Exception e) {
				LOG.error("Unable to parse timestamp '{}'", tstBase64, e);
			}
		}
		return result;
	}

	@Override
	protected List<TimestampedReference> getIndividualContentTimestampedReferences(JAdESAttribute signedAttribute) {
		// not supported
		return Collections.emptyList();
	}


	@Override
	protected boolean isAttrAuthoritiesCertValues(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isAttributeRevocationValues(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected List<CertificateRef> getCertificateRefs(JAdESAttribute unsignedAttribute) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	protected List<CRLRef> getCRLRefs(JAdESAttribute unsignedAttribute) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	protected List<OCSPRef> getOCSPRefs(JAdESAttribute unsignedAttribute) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	protected List<Identifier> getEncapsulatedCertificateIdentifiers(JAdESAttribute unsignedAttribute) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	protected List<TimestampedReference> getArchiveTimestampOtherReferences(TimestampToken timestampToken) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	protected List<Identifier> getEncapsulatedCRLIdentifiers(JAdESAttribute unsignedAttribute) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	protected List<Identifier> getEncapsulatedOCSPIdentifiers(JAdESAttribute unsignedAttribute) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	protected ArchiveTimestampType getArchiveTimestampType(JAdESAttribute unsignedAttribute) {
		// not supported
		return null;
	}

	@Override
	protected TimestampDataBuilder getTimestampDataBuilder() {
		return new JAdESTimestampDataBuilder(signature);
	}

	@Override
	protected TimestampToken makeTimestampToken(JAdESAttribute signatureAttribute, TimestampType timestampType,
			List<TimestampedReference> references) {
		throw new UnsupportedOperationException("Attribute can contain more than one timestamp");
	}

}
