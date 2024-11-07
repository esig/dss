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
package eu.europa.esig.dss.jades.validation.timestamp;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.PKIEncoding;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.validation.EtsiUComponent;
import eu.europa.esig.dss.jades.validation.JAdESAttribute;
import eu.europa.esig.dss.jades.validation.JAdESCertificateRefExtractionUtils;
import eu.europa.esig.dss.jades.validation.JAdESRevocationRefExtractionUtils;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JAdESSignedProperties;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.SignatureProperties;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.spi.validation.timestamp.SignatureTimestampSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.spi.validation.timestamp.SignatureTimestampIdentifierBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Extracts timestamps from a JAdES signature
 */
@SuppressWarnings("serial")
public class JAdESTimestampSource extends SignatureTimestampSource<JAdESSignature, JAdESAttribute> {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESTimestampSource.class);

	/** Map between time-stamp tokens and corresponding JAdES attributes */
	private final Map<TimestampToken, JAdESAttribute> timestampAttributeMap = new HashMap<>();

	/**
	 * Default constructor
	 *
	 * @param signature {@link JAdESSignature}
	 */
	public JAdESTimestampSource(final JAdESSignature signature) {
		super(signature);
	}

	@Override
	protected SignatureProperties<JAdESAttribute> buildSignedSignatureProperties() {
		return new JAdESSignedProperties(signature.getJws().getHeaders());
	}

	@Override
	@SuppressWarnings({ "unchecked", "rawtypes" })
	protected SignatureProperties<JAdESAttribute> buildUnsignedSignatureProperties() {
		return (SignatureProperties) signature.getEtsiUHeader();
	}

	@Override
	protected boolean isContentTimestamp(JAdESAttribute signedAttribute) {
		return JAdESHeaderParameterNames.ADO_TST.equals(signedAttribute.getHeaderName());
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
		return JAdESHeaderParameterNames.X_REFS.equals(unsignedAttribute.getHeaderName());
	}

	@Override
	protected boolean isAttributeCertificateRef(JAdESAttribute unsignedAttribute) {
		return JAdESHeaderParameterNames.AX_REFS.equals(unsignedAttribute.getHeaderName());
	}

	@Override
	protected boolean isCompleteRevocationRef(JAdESAttribute unsignedAttribute) {
		return JAdESHeaderParameterNames.R_REFS.equals(unsignedAttribute.getHeaderName());
	}

	@Override
	protected boolean isAttributeRevocationRef(JAdESAttribute unsignedAttribute) {
		return JAdESHeaderParameterNames.AR_REFS.equals(unsignedAttribute.getHeaderName());
	}

	@Override
	protected boolean isRefsOnlyTimestamp(JAdESAttribute unsignedAttribute) {
		return JAdESHeaderParameterNames.RFS_TST.equals(unsignedAttribute.getHeaderName());
	}

	@Override
	protected boolean isSigAndRefsTimestamp(JAdESAttribute unsignedAttribute) {
		return JAdESHeaderParameterNames.SIG_R_TST.equals(unsignedAttribute.getHeaderName());
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
		return isArchiveTimestamp(unsignedAttribute.getHeaderName());
	}
	
	private boolean isArchiveTimestamp(String headerName) {
		return JAdESHeaderParameterNames.ARC_TST.equals(headerName);
	}

	@Override
	protected boolean isTimeStampValidationData(JAdESAttribute unsignedAttribute) {
		return JAdESHeaderParameterNames.TST_VD.equals(unsignedAttribute.getHeaderName());
	}

	@Override
	protected boolean isCounterSignature(JAdESAttribute unsignedAttribute) {
		return JAdESHeaderParameterNames.C_SIG.equals(unsignedAttribute.getHeaderName());
	}
	
	@Override
	protected boolean isSignaturePolicyStore(JAdESAttribute unsignedAttribute) {
		return JAdESHeaderParameterNames.SIG_PST.equals(unsignedAttribute.getHeaderName());
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
	protected boolean isEvidenceRecord(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected List<TimestampedReference> getSignatureTimestampReferences() {
		List<TimestampedReference> timestampedReferences = super.getSignatureTimestampReferences();
		addReferences(timestampedReferences, getKeyInfoReferences());
		return timestampedReferences;
	}

	@Override
	protected List<CertificateRef> getCertificateRefs(JAdESAttribute unsignedAttribute) {
		List<CertificateRef> result = new ArrayList<>();
		List<?> certRefs = DSSJsonUtils.toList(unsignedAttribute.getValue());
		if (Utils.isCollectionNotEmpty(certRefs)) {
			for (Object item : certRefs) {
				Map<?, ?> certId = DSSJsonUtils.toMap(item, JAdESHeaderParameterNames.CERT_ID);
				if (Utils.isMapNotEmpty(certId)) {
					CertificateRef certificateRef = JAdESCertificateRefExtractionUtils.createCertificateRef(certId);
					if (certificateRef != null) {
						result.add(certificateRef);
					}
				}
			}
		}
		return result;
	}

	@Override
	protected List<CRLRef> getCRLRefs(JAdESAttribute unsignedAttribute) {
		List<CRLRef> result = new ArrayList<>();
		Map<?,?> refsValueMap = DSSJsonUtils.toMap(unsignedAttribute.getValue());
		if (Utils.isMapNotEmpty(refsValueMap)) {
			List<?> crlRefs = DSSJsonUtils.getAsList(refsValueMap, JAdESHeaderParameterNames.CRL_REFS);
			if (Utils.isCollectionNotEmpty(crlRefs)) {
				for (Object item : crlRefs) {
					Map<?, ?> crlRefMap = DSSJsonUtils.toMap(item);
					if (Utils.isMapNotEmpty(crlRefMap)) {
						CRLRef crlRef = JAdESRevocationRefExtractionUtils.createCRLRef(crlRefMap);
						if (crlRef != null) {
							result.add(crlRef);
						}
					}
				}
			}
		}
		return result;
	}

	@Override
	protected List<OCSPRef> getOCSPRefs(JAdESAttribute unsignedAttribute) {
		List<OCSPRef> result = new ArrayList<>();
		Map<?,?> refsValueMap = DSSJsonUtils.toMap(unsignedAttribute.getValue());
		if (Utils.isMapNotEmpty(refsValueMap)) {
			List<?> ocsp = DSSJsonUtils.getAsList(refsValueMap, JAdESHeaderParameterNames.OCSP_REFS);
			if (Utils.isCollectionNotEmpty(ocsp)) {
				for (Object item : ocsp) {
					Map<?, ?> ocspRefMap = DSSJsonUtils.toMap(item);
					if (Utils.isMapNotEmpty(ocspRefMap)) {
						OCSPRef ocspRef = JAdESRevocationRefExtractionUtils.createOCSPRef(ocspRefMap);
						if (ocspRef != null) {
							result.add(ocspRef);
						}
					}
				}
			}
		}
		return result;
	}

	@Override
	protected List<Identifier> getEncapsulatedCertificateIdentifiers(JAdESAttribute unsignedAttribute) {
		List<?> xVals = null;
		if (isTimeStampValidationData(unsignedAttribute)) {
			Map<?, ?> tstVd = DSSJsonUtils.toMap(unsignedAttribute.getValue(), JAdESHeaderParameterNames.TST_VD);
			if (Utils.isMapNotEmpty(tstVd)) {
				xVals = DSSJsonUtils.getAsList(tstVd, JAdESHeaderParameterNames.X_VALS);
			}
		} else {
			xVals = DSSJsonUtils.toList(unsignedAttribute.getValue(), JAdESHeaderParameterNames.X_VALS);
		}

		if (Utils.isCollectionNotEmpty(xVals)) {
			List<Identifier> certificateIdentifiers = new ArrayList<>();
			for (Object encapsulatedCert : xVals) {
				CertificateToken certificateToken = toCertificateToken(encapsulatedCert);
				if (certificateToken != null) {
					certificateIdentifiers.add(certificateToken.getDSSId());
				}
			}
			return certificateIdentifiers;
		}
		return Collections.emptyList();
	}

	private CertificateToken toCertificateToken(Object encapsulatedCert) {
		try {
			Map<?, ?> map = DSSJsonUtils.toMap(encapsulatedCert);
			if (Utils.isMapNotEmpty(map)) {
				Map<?, ?> x509Cert = DSSJsonUtils.getAsMap(map, JAdESHeaderParameterNames.X509_CERT);
				Map<?, ?> otherCert = DSSJsonUtils.getAsMap(map, JAdESHeaderParameterNames.OTHER_CERT);
				if (Utils.isMapNotEmpty(x509Cert)) {
					String base64Cert = DSSJsonUtils.getAsString(x509Cert, JAdESHeaderParameterNames.VAL);
					if (Utils.isStringNotBlank(base64Cert)) {
						byte[] binaries = Utils.fromBase64(base64Cert);
						return DSSUtils.loadCertificate(binaries);
					}

				} else if (Utils.isMapNotEmpty(otherCert)) {
					LOG.warn("The header '{}' is not supported! The entry is skipped.",
							JAdESHeaderParameterNames.OTHER_CERT);
				}
			}
		} catch (Exception e) {
			LOG.warn("An error occurred during parsing a certificate. Reason : {}", e.getMessage(), e);
		}
		return null;
	}

	@Override
	protected List<CRLBinary> getEncapsulatedCRLIdentifiers(JAdESAttribute unsignedAttribute) {
		Map<?, ?> rVals = null;
		if (isTimeStampValidationData(unsignedAttribute)) {
			Map<?, ?> tstVd = DSSJsonUtils.toMap(unsignedAttribute.getValue(), JAdESHeaderParameterNames.R_VALS);
			if (Utils.isMapNotEmpty(tstVd)) {
				rVals = DSSJsonUtils.getAsMap(tstVd, JAdESHeaderParameterNames.R_VALS);
			}
		} else {
			rVals = DSSJsonUtils.toMap(unsignedAttribute.getValue(), JAdESHeaderParameterNames.R_VALS);
		}
		if (rVals != null) {
			List<CRLBinary> crlIdentifiers = new ArrayList<>();

			List<?> crlVals = DSSJsonUtils.getAsList(rVals, JAdESHeaderParameterNames.CRL_VALS);
			if (Utils.isCollectionNotEmpty(crlVals)) {
				for (Object item : crlVals) {
					CRLBinary crlBinary = toCRLBinary(item);
					if (crlBinary != null) {
						crlIdentifiers.add(crlBinary);
					}
				}
			}
			
			return crlIdentifiers;
		}
		return Collections.emptyList();
	}

	private CRLBinary toCRLBinary(Object crlVal) {
		try {
			Map<?, ?> encapsulatedCrl = DSSJsonUtils.toMap(crlVal);
			if (Utils.isMapNotEmpty(encapsulatedCrl)) {
				String base64Crl = DSSJsonUtils.getAsString(encapsulatedCrl, JAdESHeaderParameterNames.VAL);
				if (Utils.isStringNotBlank(base64Crl)) {
					byte[] binaries = Utils.fromBase64(base64Crl);
					return CRLUtils.buildCRLBinary(binaries);
				}
			}

		} catch (Exception e) {
			LOG.warn("An error occurred during parsing a CRL. Reason : {}", e.getMessage(), e);
		}
		return null;
	}

	@Override
	protected List<OCSPResponseBinary> getEncapsulatedOCSPIdentifiers(JAdESAttribute unsignedAttribute) {
		Map<?, ?> rVals = null;
		if (isTimeStampValidationData(unsignedAttribute)) {
			Map<?, ?> tstVd = DSSJsonUtils.toMap(unsignedAttribute.getValue(), JAdESHeaderParameterNames.R_VALS);
			if (Utils.isMapNotEmpty(tstVd)) {
				rVals = DSSJsonUtils.getAsMap(tstVd, JAdESHeaderParameterNames.R_VALS);
			}
		} else {
			rVals = DSSJsonUtils.toMap(unsignedAttribute.getValue(), JAdESHeaderParameterNames.R_VALS);
		}
		if (rVals != null) {
			List<OCSPResponseBinary> ocspIdentifiers = new ArrayList<>();

			List<?> ocspVals = DSSJsonUtils.getAsList(rVals, JAdESHeaderParameterNames.OCSP_VALS);
			if (Utils.isCollectionNotEmpty(ocspVals)) {
				for (Object item : ocspVals) {
					OCSPResponseBinary ocspResponseBinary = toOCSPResponseBinary(item);
					if (ocspResponseBinary != null) {
						ocspIdentifiers.add(ocspResponseBinary);
					}
				}
			}
			
			return ocspIdentifiers;
		}
		return Collections.emptyList();
	}

	private OCSPResponseBinary toOCSPResponseBinary(Object ocspVal) {
		try {
			Map<?, ?> encapsulatedOcsp = DSSJsonUtils.toMap(ocspVal);
			if (Utils.isMapNotEmpty(encapsulatedOcsp)) {
				String base64Ocps = DSSJsonUtils.getAsString(encapsulatedOcsp, JAdESHeaderParameterNames.VAL);
				if (Utils.isStringNotBlank(base64Ocps)) {
					byte[] binaries = Utils.fromBase64(base64Ocps);
					BasicOCSPResp basicOCSPResp = DSSRevocationUtils.loadOCSPFromBinaries(binaries);
					return OCSPResponseBinary.build(basicOCSPResp);
				}
			}

		} catch (Exception e) {
			LOG.warn("An error occurred during parsing a CRL. Reason : {}", e.getMessage(), e);
		}
		return null;
	}

	@Override
	protected JAdESTimestampMessageDigestBuilder getTimestampMessageImprintDigestBuilder(TimestampToken timestampToken) {
		return new JAdESTimestampMessageDigestBuilder(signature, timestampToken)
				.setTimestampAttribute(timestampAttributeMap.get(timestampToken));
	}

	@Override
	protected JAdESTimestampMessageDigestBuilder getTimestampMessageImprintDigestBuilder(DigestAlgorithm digestAlgorithm) {
		return new JAdESTimestampMessageDigestBuilder(signature, digestAlgorithm);
	}
	
	@Override
	protected List<AdvancedSignature> getCounterSignatures(JAdESAttribute unsignedAttribute) {
		if (unsignedAttribute instanceof EtsiUComponent) {
			EtsiUComponent etsiUComponent = (EtsiUComponent) unsignedAttribute;
			JAdESSignature counterSignature = DSSJsonUtils.extractJAdESCounterSignature(etsiUComponent, signature);
			if (counterSignature != null) {
				return Collections.singletonList(counterSignature);
			}
		}
		return Collections.emptyList();
	}

	/**
	 * Returns the message-imprint digest for a SignatureTimestamp (BASE64URL(JWS Signature Value))
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm} to compute digest with
	 * @return {@link DSSMessageDigest} representing a message-imprint digest
	 */
	public DSSMessageDigest getSignatureTimestampData(DigestAlgorithm digestAlgorithm) {
		JAdESTimestampMessageDigestBuilder builder = getTimestampMessageImprintDigestBuilder(digestAlgorithm);
		return builder.getSignatureTimestampMessageDigest();
	}
	
	/**
	 * Returns message-imprint digest for an ArchiveTimestamp
	 * 
	 * @param digestAlgorithm {@link DigestAlgorithm} to compute digest with
	 * @param canonicalizationMethod {@link String} canonicalization method to use
	 * @return {@link DSSMessageDigest} representing a message-imprint digest
	 */
	public DSSMessageDigest getArchiveTimestampData(DigestAlgorithm digestAlgorithm, String canonicalizationMethod) {
		JAdESTimestampMessageDigestBuilder builder = getTimestampMessageImprintDigestBuilder(digestAlgorithm)
				.setCanonicalizationAlgorithm(canonicalizationMethod);
		return builder.getArchiveTimestampMessageDigest();
	}

	@Override
	protected TimestampToken makeTimestampToken(JAdESAttribute signatureAttribute, TimestampType timestampType,
			List<TimestampedReference> references) {
		throw new UnsupportedOperationException("Attribute can contain more than one timestamp");
	}
	
	@Override
	protected List<TimestampToken> makeTimestampTokens(JAdESAttribute signatureAttribute, TimestampType timestampType,
			List<TimestampedReference> references) {
		if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampType)) {
			return extractArchiveTimestampTokens(signatureAttribute, references);
		} else {
			Map<?, ?> tstContainer = DSSJsonUtils.toMap(signatureAttribute.getValue(), JAdESHeaderParameterNames.TST_CONTAINER);
			return extractTimestampTokens(signatureAttribute, tstContainer, timestampType, references);
		}
	}

	private List<TimestampToken> extractTimestampTokens(JAdESAttribute signatureAttribute, Map<?, ?> tstContainer,
														TimestampType timestampType, List<TimestampedReference> references) {
		final List<TimestampToken> result = new LinkedList<>();
		if (Utils.isMapNotEmpty(tstContainer)) {
			List<?> tstTokens = DSSJsonUtils.getAsList(tstContainer, JAdESHeaderParameterNames.TST_TOKENS);
			if (Utils.isCollectionNotEmpty(tstTokens)) {
				for (int i = 0; i < tstTokens.size(); i++) {
					Object tstToken = tstTokens.get(i);
					TimestampToken timestampToken = toTimestampToken(tstToken, signatureAttribute, i, timestampType, references);
					if (timestampToken != null) {
						timestampAttributeMap.put(timestampToken, signatureAttribute);
						result.add(timestampToken);
					}
				}

			} else {
				LOG.warn("'{}' element is not found! Returns an empty array if timestamps.",
						JAdESHeaderParameterNames.TST_TOKENS);
			}
		}
		return result;
	}

	private TimestampToken toTimestampToken(Object tstToken, JAdESAttribute signatureAttribute, Integer orderWithinAttribute,
											TimestampType timestampType, List<TimestampedReference> references) {
		Map<?, ?> tstTokenMap = DSSJsonUtils.toMap(tstToken);
		if (Utils.isMapNotEmpty(tstTokenMap)) {
			String encoding = DSSJsonUtils.getAsString(tstTokenMap, JAdESHeaderParameterNames.ENCODING);
			if (Utils.isStringEmpty(encoding) || Utils.areStringsEqual(PKIEncoding.DER.getUri(), encoding)) {
				String tstBase64 = DSSJsonUtils.getAsString(tstTokenMap, JAdESHeaderParameterNames.VAL);
				if (Utils.isStringNotEmpty(tstBase64)) {
					try {
						byte[] binaries = Utils.fromBase64(tstBase64);
						final SignatureTimestampIdentifierBuilder identifierBuilder = new SignatureTimestampIdentifierBuilder(binaries)
								.setSignature(signature)
								.setAttribute(signatureAttribute)
								.setOrderOfAttribute(getAttributeOrder(signatureAttribute))
								.setOrderWithinAttribute(orderWithinAttribute);
						return new TimestampToken(binaries, timestampType, references, identifierBuilder);
					} catch (Exception e) {
						LOG.warn("Unable to create timestamp from base64-encoded string '{}'. Reason : {}", tstBase64, e.getMessage(), e);
					}
				}

			} else {
				LOG.warn("Unsupported encoding {}", encoding);
			}
		}
		return null;
	}

	private List<TimestampToken> extractArchiveTimestampTokens(JAdESAttribute signatureAttribute,
															   List<TimestampedReference> references) {
		Map<?, ?> arcTst = DSSJsonUtils.toMap(signatureAttribute.getValue(), JAdESHeaderParameterNames.ARC_TST);
		return extractTimestampTokens(signatureAttribute, arcTst, TimestampType.ARCHIVE_TIMESTAMP, references);
	}

	@Override
	protected ArchiveTimestampType getArchiveTimestampType(JAdESAttribute unsignedAttribute) {
		return ArchiveTimestampType.JAdES;
	}

	@Override
	protected List<EvidenceRecord> makeEvidenceRecords(JAdESAttribute signatureAttribute, List<TimestampedReference> references) {
		if (signatureAttribute != null) {
			LOG.warn("Embedded evidence records are not supported within JAdES format! The unsigned attribute is skipped.");
		}
		return Collections.emptyList();
	}

}
