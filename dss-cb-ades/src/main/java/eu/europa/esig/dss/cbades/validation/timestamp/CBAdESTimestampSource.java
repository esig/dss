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
package eu.europa.esig.dss.cbades.validation.timestamp;

import eu.europa.esig.dss.cbades.CBAdESUtils;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.validation.CBAdESAttribute;
import eu.europa.esig.dss.cbades.validation.CBAdESSignature;
import eu.europa.esig.dss.cbades.validation.CBAdESSignedProperties;
import eu.europa.esig.dss.cbades.validation.CBAdESUHeadersComponent;
import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.SignatureProperties;
import eu.europa.esig.dss.spi.validation.timestamp.SignatureTimestampIdentifierBuilder;
import eu.europa.esig.dss.spi.validation.timestamp.SignatureTimestampSource;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Extracts timestamps from a CB-AdES signature
 *
 */
public class CBAdESTimestampSource extends SignatureTimestampSource<CBAdESSignature, CBAdESAttribute> {

    private static final Logger LOG = LoggerFactory.getLogger(CBAdESTimestampSource.class);

    /** Map between time-stamp tokens and corresponding CB-AdES attributes */
    private final Map<TimestampToken, CBAdESAttribute> timestampAttributeMap = new HashMap<>();

    /**
     * Default constructor
     *
     * @param signature {@link CBAdESSignature}
     */
    public CBAdESTimestampSource(final CBAdESSignature signature) {
        super(signature);
    }

    @Override
    protected SignatureProperties<CBAdESAttribute> buildSignedSignatureProperties() {
        if (signature.isCounterSignature() && signature.getCoseSignature().getSignerProtectedHeader() != null) {
            return new CBAdESSignedProperties(signature.getCoseSignature().getSignerProtectedHeader());
        }
        return new CBAdESSignedProperties(signature.getCoseSignature().getBodyProtectedHeader(),
                signature.getCoseSignature().getSignerProtectedHeader());
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    protected SignatureProperties<CBAdESAttribute> buildUnsignedSignatureProperties() {
        return (SignatureProperties) signature.getUHeaders();
    }

    @Override
    protected boolean isContentTimestamp(CBAdESAttribute signedAttribute) {
        return COSEHeaderParameter.ADO_TST.cbor().equals(signedAttribute.getHeaderId());
    }

    @Override
    protected boolean isAllDataObjectsTimestamp(CBAdESAttribute signedAttribute) {
        // not supported
        return false;
    }

    @Override
    protected boolean isIndividualDataObjectsTimestamp(CBAdESAttribute signedAttribute) {
        // not supported
        return false;
    }

    @Override
    protected boolean isSignatureTimestamp(CBAdESAttribute unsignedAttribute) {
        return COSEHeaderParameter.SIG_TST.cbor().equals(unsignedAttribute.getHeaderId());
    }

    @Override
    protected boolean isCompleteCertificateRef(CBAdESAttribute unsignedAttribute) {
        return false;
    }

    @Override
    protected boolean isAttributeCertificateRef(CBAdESAttribute unsignedAttribute) {
        // not supported
        return false;
    }

    @Override
    protected boolean isCompleteRevocationRef(CBAdESAttribute unsignedAttribute) {
        // not supported
        return false;
    }

    @Override
    protected boolean isAttributeRevocationRef(CBAdESAttribute unsignedAttribute) {
        // not supported
        return false;
    }

    @Override
    protected boolean isRefsOnlyTimestamp(CBAdESAttribute unsignedAttribute) {
        return COSEHeaderParameter.RFS_TST.cbor().equals(unsignedAttribute.getHeaderId());
    }

    @Override
    protected boolean isSigAndRefsTimestamp(CBAdESAttribute unsignedAttribute) {
        return COSEHeaderParameter.SIG_R_TST.cbor().equals(unsignedAttribute.getHeaderId());
    }

    @Override
    protected boolean isCertificateValues(CBAdESAttribute unsignedAttribute) {
        // not CertificateValues, but x5chain header parameter (different semantics)
        return isX5Chain(unsignedAttribute);
    }

    /**
     * Checks if the unsigned attribute corresponds to a 'x5chain' unsigned header definition
     *
     * @param unsignedAttribute {@link CBAdESAttribute} to check
     * @return TRUE if the unsigned attribute handles the 'x5chain' header parameter, FALSE otherwise
     */
    protected boolean isX5Chain(CBAdESAttribute unsignedAttribute) {
        return COSEHeaderParameter.X5CHAIN.cbor().equals(unsignedAttribute.getHeaderId());
    }

    @Override
    protected boolean isRevocationValues(CBAdESAttribute unsignedAttribute) {
        // not supported
        return false;
    }

    @Override
    protected boolean isAttrAuthoritiesCertValues(CBAdESAttribute unsignedAttribute) {
        // not supported
        return false;
    }

    @Override
    protected boolean isAttributeRevocationValues(CBAdESAttribute unsignedAttribute) {
        // not supported
        return false;
    }

    @Override
    protected boolean isArchiveTimestamp(CBAdESAttribute unsignedAttribute) {
        return COSEHeaderParameter.ARC_TST.cbor().equals(unsignedAttribute.getHeaderId());
    }

    @Override
    protected boolean isTimeStampValidationData(CBAdESAttribute unsignedAttribute) {
        // not supported
        return false;
    }

    @Override
    protected boolean isAnyValidationData(CBAdESAttribute unsignedAttribute) {
        return COSEHeaderParameter.VAL_DATA.cbor().equals(unsignedAttribute.getHeaderId());
    }

    @Override
    protected boolean isValidationDataReferences(CBAdESAttribute unsignedAttribute) {
        return COSEHeaderParameter.REFS.cbor().equals(unsignedAttribute.getHeaderId());
    }

    @Override
    protected boolean isCounterSignature(CBAdESAttribute unsignedAttribute) {
        return COSEHeaderParameter.COUNTER_SIGNATURE.cbor().equals(unsignedAttribute.getHeaderId()) ||
                COSEHeaderParameter.COUNTER_SIGNATURE0.cbor().equals(unsignedAttribute.getHeaderId()) ||
                COSEHeaderParameter.COUNTER_SIGNATURE_V2.cbor().equals(unsignedAttribute.getHeaderId()) ||
                COSEHeaderParameter.COUNTER_SIGNATURE0_V2.cbor().equals(unsignedAttribute.getHeaderId());
    }

    @Override
    protected boolean isSignaturePolicyStore(CBAdESAttribute unsignedAttribute) {
        return COSEHeaderParameter.SIG_PST.cbor().equals(unsignedAttribute.getHeaderId());
    }

    @Override
    protected boolean isEvidenceRecord(CBAdESAttribute unsignedAttribute) {
        return false;
    }

    @Override
    protected List<TimestampedReference> getSignatureTimestampReferences() {
        List<TimestampedReference> timestampedReferences = super.getSignatureTimestampReferences();
        addReferences(timestampedReferences, getKeyInfoReferences());
        return timestampedReferences;
    }

    @Override
    protected TimestampToken makeTimestampToken(CBAdESAttribute signatureAttribute, TimestampType timestampType, List<TimestampedReference> references) {
        return null;
    }

    @Override
    protected List<TimestampToken> makeTimestampTokens(CBAdESAttribute signatureAttribute, TimestampType timestampType, List<TimestampedReference> references) {
        CBORObject tstContainer = signatureAttribute.getValue();
        return extractTimestampTokens(signatureAttribute, tstContainer, timestampType, references);
    }

    private List<TimestampToken> extractTimestampTokens(CBAdESAttribute signatureAttribute, CBORObject tstContainer,
                                                        TimestampType timestampType, List<TimestampedReference> references) {
        final List<TimestampToken> result = new LinkedList<>();
        if (tstContainer != null && tstContainer.isMap()) {
            CBORArray tstTokens = ((CBORMap) tstContainer).getAsArray(COSEHeaderParameter.TST_CONTAINER_TST_TOKENS.cbor());
            if (tstTokens != null && !tstTokens.isEmpty()) {
                for (int i = 0; i < tstTokens.getSize(); i++) {
                    CBORMap tstToken = tstTokens.getAsMap(i);
                    if (tstToken == null) {
                        LOG.warn("Item of array 'tstTokens' has unsupported type! Shall be a CBOR map");
                    }
                    TimestampToken timestampToken = toTimestampToken(tstToken, signatureAttribute, i, timestampType, references);
                    if (timestampToken != null) {
                        timestampAttributeMap.put(timestampToken, signatureAttribute);
                        result.add(timestampToken);
                    }
                }

            } else {
                LOG.warn("'tstTokens' element is not found! Returns an empty array if timestamps.");
            }
        }
        return result;
    }

    private TimestampToken toTimestampToken(CBORMap tstToken, CBAdESAttribute signatureAttribute, Integer orderWithinAttribute,
                                            TimestampType timestampType, List<TimestampedReference> references) {
        if (tstToken != null) {
            String encoding = tstToken.getAsString(COSEHeaderParameter.TST_TOKEN_ENCODING.cbor());
            if (Utils.isStringNotEmpty(encoding)) {
                /*
                 * The tstToken's encoding member shall be an URI value and shall identify the encoding used for
                 * the time-stamp token. For IETF RFC 3161 [13] time-stamp tokens this member shall not be present.
                 */
                LOG.warn("Unsupported encoding of timestamp token '{}'. For IETF RFC 3161 time-stamp tokens " +
                        "the value of 'encoding' field shall not be present.", encoding);
                return null;
            }

            byte[] tstTokenVal = tstToken.getAsBinaries(COSEHeaderParameter.TST_TOKEN_VAL.cbor());
            if (tstTokenVal != null) {
                try {
                    final SignatureTimestampIdentifierBuilder identifierBuilder = new SignatureTimestampIdentifierBuilder(tstTokenVal)
                            .setSignature(signature)
                            .setAttribute(signatureAttribute)
                            .setOrderOfAttribute(getAttributeOrder(signatureAttribute))
                            .setOrderWithinAttribute(orderWithinAttribute);
                    return new TimestampToken(tstTokenVal, timestampType, references, identifierBuilder);

                } catch (Exception e) {
                    LOG.warn("Unable to create timestamp from base64-encoded string '{}'. Reason : {}",
                            Utils.toBase64(tstTokenVal), e.getMessage(), e);
                }

            } else {
                LOG.warn("No 'tstToken' value have been found. Reject the entry.");
            }

        }
        return null;
    }

    @Override
    protected List<EvidenceRecord> makeEvidenceRecords(CBAdESAttribute signatureAttribute, List<TimestampedReference> references) {
        if (signatureAttribute != null) {
            LOG.warn("Embedded evidence records are not supported within CB-AdES format! The unsigned attribute is skipped.");
        }
        return Collections.emptyList();
    }

    @Override
    protected List<Identifier> getEncapsulatedCertificateIdentifiers(CBAdESAttribute unsignedAttribute) {
        if (isAnyValidationData(unsignedAttribute)) {
            CBORObject valData = unsignedAttribute.getValue();
            if (valData.isMap()) {
                CBORMap valDataMap = (CBORMap) valData;
                CBORArray xVals = valDataMap.getAsArray(COSEHeaderParameter.VAL_DATA_X_VALS.cbor());
                if (xVals != null && !xVals.isEmpty()) {
                    List<Identifier> certificateIdentifiers = new ArrayList<>();
                    for (CBORObject encapsulatedCert : xVals.getValueAsList()) {
                        CertificateToken certificateToken = toCertificateToken(encapsulatedCert);
                        if (certificateToken != null) {
                            certificateIdentifiers.add(certificateToken.getDSSId());
                        }
                    }
                    return certificateIdentifiers;
                }

            } else {
                LOG.warn("The value of 'valData' uHeader must be represented by a CBOR Map! The entry is skipped.");
            }

        } else if (isX5Chain(unsignedAttribute)) {
            CBORObject x5chainObject = unsignedAttribute.getValue();
            if (x5chainObject.isByteString()) {
                CertificateToken certificate = loadCertificate(x5chainObject.getValueAsBytes());
                if (certificate != null) {
                    return Collections.singletonList(certificate.getDSSId());
                }

            } else if (x5chainObject.isArray()) {
                List<Identifier> certificateIdentifiers = new ArrayList<>();
                for (CBORObject cborObject : x5chainObject.getValueAsList()) {
                    if (cborObject.isByteString()) {
                        CertificateToken certificate = loadCertificate(cborObject.getValueAsBytes());
                        if (certificate != null) {
                            certificateIdentifiers.add(certificate.getDSSId());
                        }
                    } else {
                        LOG.warn("The item of 'x5chain' CBOR array shall be a byte string!");
                    }
                }
                return certificateIdentifiers;
            }
        }
        return Collections.emptyList();
    }

    private CertificateToken toCertificateToken(CBORObject encapsulatedCert) {
        if (encapsulatedCert.isMap()) {
            CBORMap x509OrOther = (CBORMap) encapsulatedCert;

            CBORMap pkiOb = x509OrOther.getAsMap(COSEHeaderParameter.X509_OR_OTHER_X509_CERT.cbor());
            byte[] val = CBAdESUtils.extractDerEncodedPkiObject(pkiOb);
            if (Utils.isArrayNotEmpty(val)) {
                return loadCertificate(val);
            }

            CBORMap otherCert = x509OrOther.getAsMap(COSEHeaderParameter.X509_OR_OTHER_OTHER_CERT.cbor());
            if (otherCert != null) {
                LOG.warn("The header 'otherCert' is not supported! The entry is skipped.");
            }

        } else {
            LOG.warn("The value of 'x509OrOther' shall be represented by a CBOR Map! Entry is skilled.");
        }
        return null;
    }

    private CertificateToken loadCertificate(byte[] binaries) {
        try {
            return DSSUtils.loadCertificate(binaries);
        } catch (Exception e) {
            LOG.warn("Unable to decode a certificate from binaries! Reason : {}", e.getMessage(), e);
            return null;
        }
    }

    @Override
    protected List<CRLBinary> getEncapsulatedCRLIdentifiers(CBAdESAttribute unsignedAttribute) {
        CBORObject valData = unsignedAttribute.getValue();
        if (valData.isMap()) {
            CBORMap valDataMap = (CBORMap) valData;
            CBORMap rVals = valDataMap.getAsMap(COSEHeaderParameter.VAL_DATA_R_VALS.cbor());
            if (rVals != null && !rVals.isEmpty()) {
                CBORArray crlVals = rVals.getAsArray(COSEHeaderParameter.R_VALS_CRL_VALS.cbor());
                if (crlVals != null && !crlVals.isEmpty()) {
                    List<CRLBinary> crlIdentifiers = new ArrayList<>();
                    for (CBORObject pkiOb : crlVals.getValueAsList()) {
                        if (pkiOb.isMap()) {
                            CRLBinary crlBinary = toCRLBinary(pkiOb);
                            if (crlBinary != null) {
                                crlIdentifiers.add(crlBinary);
                            }

                        } else {
                            LOG.warn("The header 'pkiOb' shall be represented by a CBOR Map! The entry is skipped.");
                        }
                    }
                    return crlIdentifiers;
                }
            }

        } else {
            LOG.warn("The value of header 'valData' shall be represented by a CBOR Map! Entry is skilled.");
        }
        return Collections.emptyList();
    }

    private CRLBinary toCRLBinary(CBORObject pkiOb) {
        if (pkiOb.isMap()) {
            try {
                byte[] val = CBAdESUtils.extractDerEncodedPkiObject((CBORMap) pkiOb);
                if (Utils.isArrayNotEmpty(val)) {
                    return getCrlBinary(val);
                }

            } catch (Exception e) {
                LOG.warn("An error occurred during parsing a CRL. Reason : {}", e.getMessage(), e);
            }
        } else {
            LOG.warn("The header 'pkiOb' shall be represented by a CBOR Map! The entry is skipped.");
        }
        return null;
    }

    private static CRLBinary getCrlBinary(byte[] val) {
        try {
            return CRLUtils.buildCRLBinary(val);
        } catch (Exception e) {
            LOG.warn("Unable to decode a CRL from binaries! Reason : {}", e.getMessage(), e);
            return null;
        }
    }

    @Override
    protected List<OCSPResponseBinary> getEncapsulatedOCSPIdentifiers(CBAdESAttribute unsignedAttribute) {
        CBORObject valData = unsignedAttribute.getValue();
        if (valData.isMap()) {
            CBORMap valDataMap = (CBORMap) valData;
            CBORMap rVals = valDataMap.getAsMap(COSEHeaderParameter.VAL_DATA_R_VALS.cbor());
            if (rVals != null && !rVals.isEmpty()) {
                List<OCSPResponseBinary> ocspIdentifiers = new ArrayList<>();

                CBORArray ocspVals = rVals.getAsArray(COSEHeaderParameter.R_VALS_OCSP_VALS.cbor());
                if (ocspVals != null && !ocspVals.isEmpty()) {
                    for (CBORObject pkiOb : ocspVals.getValueAsList()) {
                        if (pkiOb.isMap()) {
                            OCSPResponseBinary ocspResponseBinary = toOCSPResponseBinary(pkiOb);
                            if (ocspResponseBinary != null) {
                                ocspIdentifiers.add(ocspResponseBinary);
                            }
                        } else {
                            LOG.warn("The header 'pkiOb' shall be represented by a CBOR Map! The entry is skipped.");
                        }
                    }
                }
                return ocspIdentifiers;
            }

        } else {
            LOG.warn("The value of header 'valData' shall be represented by a CBOR Map! Entry is skilled.");
        }

        return Collections.emptyList();
    }

    private OCSPResponseBinary toOCSPResponseBinary(CBORObject pkiOb) {
        if (pkiOb.isMap()) {
            try {
                byte[] val = CBAdESUtils.extractDerEncodedPkiObject((CBORMap) pkiOb);
                if (Utils.isArrayNotEmpty(val)) {
                    return getOcspResponseBinary(val);
                }

            } catch (Exception e) {
                LOG.warn("An error occurred during parsing an OCSP response. Reason : {}", e.getMessage(), e);
            }
        } else {
            LOG.warn("The header 'pkiOb' shall be represented by a CBOR Map! The entry is skipped.");
        }
        return null;
    }

    private static OCSPResponseBinary getOcspResponseBinary(byte[] val) {
        try {
            return OCSPResponseBinary.build(DSSRevocationUtils.loadOCSPFromBinaries(val));
        } catch (Exception e) {
            LOG.warn("Unable to decode an OCSP response from binaries! Reason : {}", e.getMessage(), e);
            return null;
        }
    }

    @Override
    protected List<CertificateRef> getCertificateRefs(CBAdESAttribute unsignedAttribute) {
        CBORObject refs = unsignedAttribute.getValue();
        if (refs.isMap()) {
            if (refs.isMap()) {
                CBORMap refsMap = (CBORMap) refs;
                CBORArray xRefs = refsMap.getAsArray(COSEHeaderParameter.REFS_X_REFS.cbor());
                if (xRefs != null && !xRefs.isEmpty()) {
                    List<CertificateRef> certificateRefs = new ArrayList<>();
                    for (CBORObject item : xRefs.getValueAsList()) {
                        if (item.isMap()) {
                            CBORMap certId = (CBORMap) item;
                            CertificateRef certificateRef = CBAdESUtils.fromCertId(certId);
                            if (certificateRef != null) {
                                certificateRefs.add(certificateRef);
                            }
                        } else {
                            LOG.warn("The value of 'CertId' shall be represented by a CBOR Map! Entry is skilled.");
                        }
                    }
                    return certificateRefs;
                }

            } else {
                LOG.warn("The value of header 'refs' shall be represented by a CBOR Map! Entry is skilled.");
            }
        }
        return Collections.emptyList();
    }

    @Override
    protected List<CRLRef> getCRLRefs(CBAdESAttribute unsignedAttribute) {
        CBORObject refs = unsignedAttribute.getValue();
        if (refs.isMap()) {
            if (refs.isMap()) {
                CBORMap refsMap = (CBORMap) refs;
                CBORMap rRefs = refsMap.getAsMap(COSEHeaderParameter.REFS_R_REFS.cbor());
                if (rRefs != null && !rRefs.isEmpty()) {
                    CBORArray crlRefs = rRefs.getAsArray(COSEHeaderParameter.R_REFS_CRL_REF.cbor());
                    if (crlRefs != null) {
                        List<CRLRef> result = new ArrayList<>();
                        for (CBORObject item : crlRefs.getValueAsList()) {
                            if (item.isMap()) {
                                CBORMap crlRefMap = (CBORMap) item;
                                CRLRef crlRef = CBAdESUtils.createCRLRef(crlRefMap);
                                if (crlRef != null) {
                                    result.add(crlRef);
                                }
                            } else {
                                LOG.warn("The value of 'CRLRef' shall be represented by a CBOR Map! Entry is skilled.");
                            }
                        }
                        return result;
                    }
                }

            } else {
                LOG.warn("The value of header 'refs' shall be represented by a CBOR Map! Entry is skilled.");
            }
        }
        return Collections.emptyList();
    }

    @Override
    protected List<OCSPRef> getOCSPRefs(CBAdESAttribute unsignedAttribute) {
        CBORObject refs = unsignedAttribute.getValue();
        if (refs.isMap()) {
            if (refs.isMap()) {
                CBORMap refsMap = (CBORMap) refs;
                CBORMap rRefs = refsMap.getAsMap(COSEHeaderParameter.REFS_R_REFS.cbor());
                if (rRefs != null && !rRefs.isEmpty()) {
                    CBORArray ocspRefs = rRefs.getAsArray(COSEHeaderParameter.R_REFS_OCSP_REF.cbor());
                    if (ocspRefs != null) {
                        List<OCSPRef> result = new ArrayList<>();
                        for (CBORObject item : ocspRefs.getValueAsList()) {
                            if (item.isMap()) {
                                CBORMap ocspRefMap = (CBORMap) item;
                                OCSPRef ocspRef = CBAdESUtils.createOCSPRef(ocspRefMap);
                                if (ocspRef != null) {
                                    result.add(ocspRef);
                                }
                            } else {
                                LOG.warn("The value of 'OCSPRef' shall be represented by a CBOR Map! Entry is skilled.");
                            }
                        }
                        return result;
                    }
                }

            } else {
                LOG.warn("The value of header 'refs' shall be represented by a CBOR Map! Entry is skilled.");
            }
        }
        return Collections.emptyList();
    }

    @Override
    protected List<AdvancedSignature> getCounterSignatures(CBAdESAttribute unsignedAttribute) {
        if (unsignedAttribute instanceof CBAdESUHeadersComponent) {
            CBAdESUHeadersComponent cbadesUHeadersComponent = (CBAdESUHeadersComponent) unsignedAttribute;
            List<CBAdESSignature> counterSignatures = CBAdESUtils.buildCounterSignatures(signature, cbadesUHeadersComponent);
            if (Utils.isCollectionNotEmpty(counterSignatures)) {
                return new ArrayList<>(counterSignatures);
            }
        }
        return Collections.emptyList();
    }

    @Override
    protected ArchiveTimestampType getArchiveTimestampType(CBAdESAttribute unsignedAttribute) {
        return ArchiveTimestampType.CB_AdES;
    }

    @Override
    protected CBAdESTimestampMessageDigestBuilder getTimestampMessageImprintDigestBuilder(TimestampToken timestampToken) {
        return new CBAdESTimestampMessageDigestBuilder(signature, timestampToken)
                .setTimestampAttribute(timestampAttributeMap.get(timestampToken));
    }

    @Override
    protected CBAdESTimestampMessageDigestBuilder getTimestampMessageImprintDigestBuilder(DigestAlgorithm digestAlgorithm) {
        return new CBAdESTimestampMessageDigestBuilder(signature, digestAlgorithm);
    }

    /**
     * Returns the message-imprint digest for a SignatureTimestamp (BASE64URL(JWS Signature Value))
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to compute digest with
     * @return {@link DSSMessageDigest} representing a message-imprint digest
     */
    public DSSMessageDigest getSignatureTimestampData(DigestAlgorithm digestAlgorithm) {
        CBAdESTimestampMessageDigestBuilder builder = getTimestampMessageImprintDigestBuilder(digestAlgorithm);
        return builder.getSignatureTimestampMessageDigest();
    }

    /**
     * Returns message-imprint digest for an ArchiveTimestamp
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to compute digest with
     * @return {@link DSSMessageDigest} representing a message-imprint digest
     */
    public DSSMessageDigest getArchiveTimestampData(DigestAlgorithm digestAlgorithm) {
        CBAdESTimestampMessageDigestBuilder builder = getTimestampMessageImprintDigestBuilder(digestAlgorithm);
        return builder.getArchiveTimestampMessageDigest();
    }

}
