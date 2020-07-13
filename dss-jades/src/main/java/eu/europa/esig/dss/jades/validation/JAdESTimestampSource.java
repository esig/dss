package eu.europa.esig.dss.jades.validation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.PKIEncoding;
import eu.europa.esig.dss.enumerations.TimestampLocation;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.jades.JAdESArchiveTimestampType;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRL;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ListRevocationSource;
import eu.europa.esig.dss.validation.SignatureProperties;
import eu.europa.esig.dss.validation.timestamp.AbstractTimestampSource;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;

@SuppressWarnings("serial")
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
	protected SignatureProperties<JAdESAttribute> getUnsignedSignatureProperties() {
		List<Object> etsiU = JAdESUtils.getEtsiU(signature.getJws());
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
		final List<TimestampedReference> encapsulatedReferences = new ArrayList<>();
		
		// contains references to the last 'arcTst' and the associated 'tstVd'
		List<TimestampedReference> previousArcTstReferences = new ArrayList<>();

		final List<JAdESAttribute> unsignedAttributes = unsignedSignatureProperties.getAttributes();
		for (JAdESAttribute unsignedAttribute : unsignedAttributes) {

			List<TimestampToken> currentTimestamps = null;

			if (isSignatureTimestamp(unsignedAttribute)) {

				currentTimestamps = extractTimestampTokens(unsignedAttribute, TimestampType.SIGNATURE_TIMESTAMP,
						getSignatureTimestampReferences());

				if (Utils.isCollectionNotEmpty(currentTimestamps)) {
					signatureTimestamps.addAll(currentTimestamps);
				}
			} else if (isCertificateValues(unsignedAttribute)) {
				addReferences(encapsulatedReferences, getTimestampedCertificateValues(unsignedAttribute));
				continue;

			} else if (isRevocationValues(unsignedAttribute)) {
				addReferences(encapsulatedReferences, getTimestampedRevocationValues(unsignedAttribute));
				continue;

			} else if (isAttrAuthoritiesCertValues(unsignedAttribute)) {
				addReferences(encapsulatedReferences, getTimestampedCertificateValues(unsignedAttribute));
				continue;

			} else if (isAttributeRevocationValues(unsignedAttribute)) {
				addReferences(encapsulatedReferences, getTimestampedRevocationValues(unsignedAttribute));
				continue;
				
			} else if (isArchiveTimestamp(unsignedAttribute)) {
				final List<TimestampedReference> references = new ArrayList<>();
				addReferences(references, previousArcTstReferences);
				
				// reset the list, because a new 'arcTst' has been found
				previousArcTstReferences = new ArrayList<>();
				
				ArchiveTimestampType archiveTimestampType = getArchiveTimestampType(unsignedAttribute);
				if (archiveTimestampType != null) {
					switch (archiveTimestampType) {
						case JAdES_ALL:
							addReferencesForPreviousTimestamps(references, timestamps);
							addReferences(references, encapsulatedReferences);
							break;
						case JAdES_PREVIOUS_ARC_TST:
							// do nothing, previousArcTst references has been already added
							break;
						default:
							LOG.warn("Unsupported ArchiveTimestampType '{}'. Timestamp(s) is skipped.", archiveTimestampType);
							previousArcTstReferences = new ArrayList<>();
							continue;
					}
					
					currentTimestamps = extractArchiveTimestampTokens(unsignedAttribute, references);

					if (Utils.isCollectionNotEmpty(currentTimestamps)) {
						for (TimestampToken timestampToken : currentTimestamps) {
							timestampToken.setArchiveTimestampType(archiveTimestampType);
						}
						archiveTimestamps.addAll(currentTimestamps);
						
						addReferencesForPreviousTimestamps(previousArcTstReferences, currentTimestamps);
					}
				}
				
				continue;
				
			} else if (isTimeStampValidationData(unsignedAttribute)) {
				List<TimestampedReference> timestampValidationData = getTimestampValidationData(unsignedAttribute);
				addReferences(encapsulatedReferences, timestampValidationData);

				// required for Archive TSTs of PREVIOUS_ARC_TST type
				addReferences(previousArcTstReferences, timestampValidationData);
				
				continue;
				
			} else {
				LOG.warn("The unsigned attribute with name [{}] is not supported", unsignedAttribute.getHeaderName());
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
		return JAdESHeaderParameterNames.X_VALS.equals(unsignedAttribute.getHeaderName());
	}

	@Override
	protected boolean isRevocationValues(JAdESAttribute unsignedAttribute) {
		return JAdESHeaderParameterNames.R_VALS.equals(unsignedAttribute.getHeaderName());
	}

	@Override
	protected boolean isArchiveTimestamp(JAdESAttribute unsignedAttribute) {
		return JAdESHeaderParameterNames.ARC_TST.equals(unsignedAttribute.getHeaderName());
	}

	@Override
	protected boolean isTimeStampValidationData(JAdESAttribute unsignedAttribute) {
		return JAdESHeaderParameterNames.TST_VD.equals(unsignedAttribute.getHeaderName());
	}

	@SuppressWarnings("unchecked")
	private List<TimestampToken> extractTimestampTokens(JAdESAttribute signatureAttribute, TimestampType timestampType,
			List<TimestampedReference> references) {
		Map<String, Object> tstContainer = (Map<String, Object>) signatureAttribute.getValue();
		return extractTimestampTokens(tstContainer, timestampType, references);
	}

	@SuppressWarnings("unchecked")
	private List<TimestampToken> extractTimestampTokens(Map<String, Object> tstContainer, TimestampType timestampType,
			List<TimestampedReference> references) {
		List<TimestampToken> result = new LinkedList<TimestampToken>();

		List<Map<String, Object>> tokens = (List<Map<String, Object>>) tstContainer.get(JAdESHeaderParameterNames.TS_TOKENS);

		for (Map<String, Object> jsonToken : tokens) {
			String encoding = (String) jsonToken.get(JAdESHeaderParameterNames.ENCODING);
			if (Utils.isStringEmpty(encoding) || Utils.areStringsEqual(PKIEncoding.DER.getUri(), encoding)) {
				String tstBase64 = (String) jsonToken.get(JAdESHeaderParameterNames.VAL);
				try {
					result.add(new TimestampToken(Utils.fromBase64(tstBase64), timestampType, references, TimestampLocation.JAdES));
				} catch (Exception e) {
					LOG.error("Unable to parse timestamp '{}'", tstBase64, e);
				}
			} else {
				LOG.warn("Unsupported encoding {}", encoding);
			}
		}
		return result;
	}

	@SuppressWarnings("unchecked")
	private List<TimestampToken> extractArchiveTimestampTokens(JAdESAttribute signatureAttribute, List<TimestampedReference> references) {
		Map<String, Object> arcTst = (Map<String, Object>) signatureAttribute.getValue();
		Map<String, Object> tstContainer = (Map<String, Object>) arcTst.get(JAdESHeaderParameterNames.TST_CONTAINER);
		
		int hashCode = signatureAttribute.getValueHashCode();
		List<TimestampToken> timestampTokens = extractTimestampTokens(tstContainer, TimestampType.ARCHIVE_TIMESTAMP, references);
		for (TimestampToken timestampToken : timestampTokens) {
			timestampToken.setHashCode(hashCode);
		}
		return timestampTokens;
	}

	@Override
	protected List<TimestampedReference> getIndividualContentTimestampedReferences(JAdESAttribute signedAttribute) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	protected boolean isAttrAuthoritiesCertValues(JAdESAttribute unsignedAttribute) {
		return JAdESHeaderParameterNames.AX_VALS.equals(unsignedAttribute.getHeaderName());
	}

	@Override
	protected boolean isAttributeRevocationValues(JAdESAttribute unsignedAttribute) {
		return JAdESHeaderParameterNames.AR_VALS.equals(unsignedAttribute.getHeaderName());
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
	@SuppressWarnings("unchecked")
	protected List<Identifier> getEncapsulatedCertificateIdentifiers(JAdESAttribute unsignedAttribute) {
		List<Object> xVals = null;
		if (isTimeStampValidationData(unsignedAttribute)) {
			Map<String, Object> tstVd = (Map<String, Object>) unsignedAttribute.getValue();
			xVals = (List<Object>) tstVd.get(JAdESHeaderParameterNames.CERT_VALS);
		} else {
			xVals = (List<Object>) unsignedAttribute.getValue();
		}
		if (xVals != null) {
			List<Identifier> certificateIdentifiers = new ArrayList<>();
			
			for (Object encapsulatedCert : xVals) {
				try {
					Map<String, Object> map = (Map<String, Object>) encapsulatedCert;
					Map<String, Object> certObject = (Map<String, Object>) map.get(JAdESHeaderParameterNames.X509_CERT);
					if (certObject == null) {
						certObject = (Map<String, Object>) map.get(JAdESHeaderParameterNames.OTHER_CERT);
					}
					String base64Cert = (String) certObject.get(JAdESHeaderParameterNames.VAL);
					if (base64Cert != null) {
						byte[] binaries = Utils.fromBase64(base64Cert);
						CertificateToken certificateToken = DSSUtils.loadCertificate(binaries);
						certificateIdentifiers.add(certificateToken.getDSSId());
					}
				} catch (Exception e) {
					LOG.warn("An error occurred during parsing a certificate. Reason : {}", e.getMessage(), e);
				}
			}
			
			return certificateIdentifiers;
		}
		return Collections.emptyList();
	}

	@Override
	protected List<TimestampedReference> getArchiveTimestampOtherReferences(TimestampToken timestampToken) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	@SuppressWarnings("unchecked")
	protected List<Identifier> getEncapsulatedCRLIdentifiers(JAdESAttribute unsignedAttribute) {
		Map<String, Object> rVals = null;
		if (isTimeStampValidationData(unsignedAttribute)) {
			Map<String, Object> tstVd = (Map<String, Object>) unsignedAttribute.getValue();
			rVals = (Map<String, Object>) tstVd.get(JAdESHeaderParameterNames.REV_VALS);
		} else {
			rVals = (Map<String, Object>) unsignedAttribute.getValue();
		}
		if (rVals != null) {
			List<Identifier> crlIdentifiers = new ArrayList<>();
			
			List<Object> crlVals = (List<Object>) rVals.get(JAdESHeaderParameterNames.CRL_VALS);
			
			if (Utils.isCollectionNotEmpty(crlVals)) {
				for (Object encapsulatedCrl : crlVals) {
					try {
						Map<String, Object> map = (Map<String, Object>) encapsulatedCrl;
						String base64Crl = (String) map.get(JAdESHeaderParameterNames.VAL);
						if (base64Crl != null) {
							byte[] binaries = Utils.fromBase64(base64Crl);
							crlIdentifiers.add(CRLUtils.buildCRLBinary(binaries));
						}
					} catch (Exception e) {
						LOG.warn("An error occurred during parsing a CRL. Reason : {}", e.getMessage(), e);
					}
				}
			}
			
			return crlIdentifiers;
		}
		return Collections.emptyList();
	}

	@Override
	@SuppressWarnings("unchecked")
	protected List<Identifier> getEncapsulatedOCSPIdentifiers(JAdESAttribute unsignedAttribute) {
		Map<String, Object> rVals = null;
		if (isTimeStampValidationData(unsignedAttribute)) {
			Map<String, Object> tstVd = (Map<String, Object>) unsignedAttribute.getValue();
			rVals = (Map<String, Object>) tstVd.get(JAdESHeaderParameterNames.REV_VALS);
		} else {
			rVals = (Map<String, Object>) unsignedAttribute.getValue();
		}
		if (rVals != null) {
			List<Identifier> ocspIdentifiers = new ArrayList<>();
			
			List<Object> ocspVals = (List<Object>) rVals.get(JAdESHeaderParameterNames.OCSP_VALS);
			
			if (Utils.isCollectionNotEmpty(ocspVals)) {
				for (Object encapsulatedOcsp : ocspVals) {
					try {
						Map<String, Object> map = (Map<String, Object>) encapsulatedOcsp;
						String base64Ocps = (String) map.get(JAdESHeaderParameterNames.VAL);
						if (base64Ocps != null) {
							byte[] binaries = Utils.fromBase64(base64Ocps);
							BasicOCSPResp basicOCSPResp = DSSRevocationUtils.loadOCSPFromBinaries(binaries);
							ocspIdentifiers.add(OCSPResponseBinary.build(basicOCSPResp));
						}
					} catch (Exception e) {
						LOG.warn("An error occurred during parsing a CRL. Reason : {}", e.getMessage(), e);
					}
				}
			}
			
			return ocspIdentifiers;
		}
		return Collections.emptyList();
	}

	@Override
	@SuppressWarnings("unchecked")
	protected ArchiveTimestampType getArchiveTimestampType(JAdESAttribute unsignedAttribute) {
		/*
		 * 5.3.6.3	Computation of message-imprint
		 * Absence of timeStamped shall be treated as if it is present with value "all".
		 */
		ArchiveTimestampType archiveTimestampType = ArchiveTimestampType.JAdES_ALL;
		
		Map<String, Object> arcTst = (Map<String, Object>) unsignedAttribute.getValue();
		String timestamped = (String) arcTst.get(JAdESHeaderParameterNames.TIMESTAMPED);
		if (timestamped != null) {
			switch (JAdESArchiveTimestampType.forJsonValue(timestamped)) {
				case TIMESTAMPED_ALL:
					return ArchiveTimestampType.JAdES_ALL;
				case TIMESTAMPED_PREVIOUS_ARC_TST:
					return ArchiveTimestampType.JAdES_PREVIOUS_ARC_TST;
				default:
					LOG.warn("Unsupported 'arcTst.timestamped' type found : {}. The default value 'all' will be used.", timestamped);
			}
		}
		
		return archiveTimestampType;
	}

	@Override
	protected JAdESTimestampDataBuilder getTimestampDataBuilder() {
		return new JAdESTimestampDataBuilder(signature);
	}
	
	/**
	 * Returns concatenated data for an ArchiveTimestamp
	 * 
	 * @param canonicalizationMethod {@link String} canonicalization method to use
	 * @param archiveTimestampType {@link JAdESArchiveTimestampType}
	 * @return byte array
	 */
	public byte[] getArchiveTimestampData(String canonicalizationMethod, JAdESArchiveTimestampType archiveTimestampType) {
		return getTimestampDataBuilder().getArchiveTimestampData(canonicalizationMethod, archiveTimestampType);
	}

	@Override
	protected TimestampToken makeTimestampToken(JAdESAttribute signatureAttribute, TimestampType timestampType,
			List<TimestampedReference> references) {
		throw new UnsupportedOperationException("Attribute can contain more than one timestamp");
	}

}
