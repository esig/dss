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
package eu.europa.esig.dss.cbades;

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.ec.digit.cddl4j.cbor.CBORTags;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.cbades.CBAdESSchemaUtils;
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.validation.CBAdESSignature;
import eu.europa.esig.dss.cbades.validation.CBAdESUHeadersComponent;
import eu.europa.esig.dss.cbades.validation.CBORSignature;
import eu.europa.esig.dss.enumerations.COSESignatureType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.ObjectIdentifier;
import eu.europa.esig.dss.enumerations.PKIEncoding;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Utility class containing methods for CB-AdES processing
 *
 */
public class CBAdESUtils {

    private static final Logger LOG = LoggerFactory.getLogger(CBAdESUtils.class);

    /**
     * Utils class
     */
    private CBAdESUtils() {
        // empty
    }

    /**
     * Creates an 'oid' object according to TS 119-152 ch. 5.4.1 The oId data type
     *
     * @param objectIdentifier {@link ObjectIdentifier} to create an 'oid' from
     * @return {@link eu.europa.ec.digit.cddl4j.cbor.CBORValue} 'oid' object
     */
    public static CBORValue getOidObject(ObjectIdentifier objectIdentifier) {
        return getOidObject(DSSUtils.getUriOrUrnOid(objectIdentifier), objectIdentifier.getDescription(),
                objectIdentifier.getDocumentationReferences());
    }

    /**
     * Creates an 'oid' JsonObject according to TS 119-182 ch. 5.4.1 The oId data type
     *
     * @param uri {@link String} URI defining the object. The property is REQUIRED.
     * @param desc {@link String} the object description. The property is OPTIONAL.
     * @param docRefs an array of {@link String} URIs containing any other additional information about the object.
     * 				The property is OPTIONAL.
     * @return {@link CBORValue} 'oid' object
     */
    public static CBORValue getOidObject(String uri, String desc, String[] docRefs) {
        Objects.requireNonNull(uri, "uri must be defined!");

        CBORValue.CBORMapEditor oidParams = CBOR.map();
        oidParams.put(COSEHeaderParameter.OID_ID.cbor(), CBORTags.uri(uri));
        if (Utils.isStringNotEmpty(desc)) {
            oidParams.put(COSEHeaderParameter.OID_DESC.cbor(), desc);
        }
        if (Utils.isArrayNotEmpty(docRefs)) {
            CBORValue[] cborDocRefs = new CBORValue[docRefs.length];
            for (int i = 0; i < docRefs.length; i++) {
                cborDocRefs[i] = CBORTags.uri(docRefs[i]);
            }
            oidParams.put(COSEHeaderParameter.OID_DOC_REFS.cbor(), CBOR.array(cborDocRefs).value());
        }

        return oidParams.value();
    }

    /**
     * Creates a 'tstContainer' JsonObject according to TS 119-152 ch. 5.4.3.3 The tstContainer type
     *
     * @param timestampBinaries a list of {@link TimestampBinary}s to incorporate
     * @return {@link CBORValue} 'tstContainer' object
     */
    public static CBORValue getTstContainer(List<TimestampBinary> timestampBinaries) {
        if (Utils.isCollectionEmpty(timestampBinaries)) {
            throw new IllegalArgumentException("Impossible to create 'tstContainer'. List of TimestampBinaries cannot be null or empty!");
        }

        CBORValue.CBORArrayEditor tstTokens = CBOR.array();
        for (TimestampBinary timestampBinary : timestampBinaries) {
            CBORValue tstToken = getTstToken(timestampBinary);
            tstTokens.add(tstToken);
        }
        return CBOR.map()
                .put(COSEHeaderParameter.TST_CONTAINER_TST_TOKENS.cbor(), tstTokens.value())
                .value();
    }

    /**
     * Creates a 'tstToken' CBOR Map according to TS 119-152 ch. 5.4.3.3 The tstContainer type
     *
     * @param timestampBinary {@link TimestampBinary}s to incorporate
     * @return {@link CBORValue} 'tstToken' object
     */
    private static CBORValue getTstToken(TimestampBinary timestampBinary) {
        Objects.requireNonNull(timestampBinary, "timestampBinary cannot be null!");

        // only RFC 3161 TimestampTokens are supported
        // 'type', 'encoding' and 'specRef' params are not need to be defined (see TS 119 152-1 ch. 5.4.3.3)
        return CBOR.map()
                .put(COSEHeaderParameter.TST_TOKEN_VAL.cbor(), timestampBinary.getBytes())
                .value();
    }

    /**
     * This method concatenates {@code DSSDocument} contents in a single byte array
     *
     * @param documents a list of {@link DSSDocument}s to concatenate
     * @return a byte array
     */
    public static byte[] concatenateDSSDocuments(List<DSSDocument> documents) {
        if (Utils.isCollectionEmpty(documents)) {
            throw new IllegalArgumentException("Unable to build a COSE Payload. Reason : the detached content is not provided!");
        }
        if (documents.size() == 1) {
            return DSSUtils.toByteArray(documents.get(0));
        }
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            for (DSSDocument document : documents) {
                baos.write(DSSUtils.toByteArray(document));
            }
            return baos.toByteArray();

        } catch (IOException e) {
            throw new DSSException(String.format("Unable to build a COSE Payload. Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * Extracts {@code Digest} from a 'DigAlgVal' CBOR Array
     *
     * @param digAlgVal {@link CBORArray}
     * @return {@link Digest}
     * @deprecated since DSS 6.6. Use {@link #getDigestAlgAndVal(CBORValue)}
     */
    @Deprecated
    public static Digest getDigestAlgAndVal(CBORArray digAlgVal) {
        if (digAlgVal != null) {
            return getDigestAlgAndVal(digAlgVal.toCBORValue());
        }
        return null;
    }

    /**
     * Extracts {@code Digest} from a 'DigAlgVal' CBOR Array
     *
     * @param digAlgVal {@link CBORValue}
     * @return {@link Digest}
     */
    public static Digest getDigestAlgAndVal(CBORValue digAlgVal) {
        if (digAlgVal != null) {
            if (digAlgVal.size() == 2) {
                CBORValue digAlgValHashAlg = digAlgVal.get(COSEConstants.DIG_ALG_VAL_HASH_ALG);
                Long hashAlg = getHashAlgorithmId(digAlgValHashAlg);
                if (hashAlg == null) {
                    LOG.warn("Unable to extract hashAlg. See previous log messages.");
                    return null;
                }
                DigestAlgorithm digestAlgorithm = CBORUtils.getDigestAlgorithmForCoseId(hashAlg);
                byte[] hashValue = digAlgVal.getAsBytesOrNull(COSEConstants.DIG_ALG_VAL_HASH_VALUE);
                if (digestAlgorithm != null && hashValue != null) {
                    return new Digest(digestAlgorithm, hashValue);
                } else {
                    LOG.warn("DigAlgVal shall by of type [ hashAlg: (int / tstr), hashValue: bstr ].");
                }
            } else {
                LOG.warn("Invalid number of entries within 'DigAlgVal' array! Shall by of type [ hashAlg: (int / tstr), hashValue: bstr ].");
            }
        }
        return null;
    }

    private static Long getHashAlgorithmId(CBORValue hashAlg) {
        if (hashAlg == null) {
            return null;
        }
        if (hashAlg.isInteger()) {
            return hashAlg.asInteger().longValue();
        } else if (hashAlg.isTextString()) {
            String itemAsString = hashAlg.asString();
            try {
                return Long.parseLong(itemAsString);
            } catch (NumberFormatException e) {
                LOG.debug("Unable to decode CBOR String '{}' to Long : {}", itemAsString, e.getMessage());
            }
        } else {
            LOG.warn("Unsupported type of hash algorithm CBOR item : {}", hashAlg.getType());
        }
        return null;
    }

    /**
     * Parses the 'certId' value and returns {@code CertificateRef}
     *
     * @param certId {@link CBORMap} representing the item of 'xRefs' array
     * @return {@link CertificateRef} of the value has been parsed successfully, FALSE otherwise
     * @deprecated since DSS 6.6. Use {@link #fromCertId(CBORValue)}
     */
    @Deprecated
    public static CertificateRef fromCertId(CBORMap certId) {
        if (certId != null) {
            return fromCertId(certId.toCBORValue());
        }
        return null;
    }

    /**
     * Parses the 'certId' value and returns {@code CertificateRef}
     *
     * @param certId {@link CBORValue} representing the item of 'xRefs' array
     * @return {@link CertificateRef} of the value has been parsed successfully, FALSE otherwise
     */
    public static CertificateRef fromCertId(CBORValue certId) {
        CBORValue x5t = certId.getAsArrayOrNull(COSEHeaderParameter.CERT_ID_X5T.cbor());
        Digest digest = extractX5TDigest(x5t);
        if (digest != null) {
            final CertificateRef certificateRef = new CertificateRef();
            certificateRef.setCertDigest(digest);

            byte[] kid = certId.getAsBytesOrNull(COSEHeaderParameter.CERT_ID_KID.cbor());
            if (kid != null) {
                IssuerSerial issuerSerial = CBORUtils.getIssuerSerial(kid);
                if (issuerSerial != null) {
                    certificateRef.setCertificateIdentifier(DSSASN1Utils.toSignerIdentifier(issuerSerial));
                } else {
                    certificateRef.setKid(Utils.toBase64(kid));
                }
            }

            String x5u = certId.getAsStringOrNull(COSEHeaderParameter.CERT_ID_X5U.cbor());
            if (x5u != null) {
                certificateRef.setX509Url(x5u);
            }

            return certificateRef;

        } else {
            LOG.warn("The mandatory header 'x5t' is not present within a 'CertId' entry! The entry is skipped.");
        }
        return null;
    }

    /**
     * Extracts Digest value from the 'x5t' CBOR array
     *
     * @param x5t {@link CBORArray} to parse
     * @return {@link Digest}
     * @deprecated since DSS 6.6. Use {@link #extractX5TDigest(CBORValue)}
     */
    @Deprecated
    public static Digest extractX5TDigest(CBORArray x5t) {
        if (x5t != null) {
            return extractX5TDigest(x5t.toCBORValue());
        }
        return null;
    }

    /**
     * Extracts Digest value from the 'x5t' CBOR array
     *
     * @param x5t {@link CBORValue} to parse
     * @return {@link Digest}
     */
    public static Digest extractX5TDigest(CBORValue x5t) {
        if (x5t != null) {
            if (x5t.size() == 2) {
                CBORValue coseCertHashAlg = x5t.get(COSEConstants.COSE_CERT_HASH_ALG);
                Long hashAlgId = getHashAlgorithmId(coseCertHashAlg);
                if (hashAlgId == null) {
                    LOG.warn("Unable to extract 'x5t' hashAlg. See previous log messages.");
                    return null;
                }
                DigestAlgorithm hashAlg = CBORUtils.getDigestAlgorithmForCoseId(hashAlgId);
                byte[] hashValue = x5t.getAsBytesOrNull(COSEConstants.COSE_CERT_HASH_VALUE);
                if (hashAlg != null && hashValue != null) {
                    return new Digest(hashAlg, hashValue);

                } else {
                    LOG.warn("'x5t' header array members have invalid structure!");
                }

            } else {
                LOG.warn("'x5t' header array shall have two entries!");
            }
        }
        return null;
    }

    /**
     * Parses the 'pkiOb' CBOR map and returns the extracted DER-encoded binaries
     *
     * @param pkiOb {@link CBORMap} to parse
     * @return byte array containing DER-encoded value, if supported
     * @deprecated since DSS 6.6. Use {@link #extractDerEncodedPkiObject(CBORValue)} instead.
     */
    @Deprecated
    public static byte[] extractDerEncodedPkiObject(CBORMap pkiOb) {
        if (pkiOb != null) {
            return extractDerEncodedPkiObject(pkiOb.toCBORValue());
        }
        return null;
    }

    /**
     * Parses the 'pkiOb' CBOR map and returns the extracted DER-encoded binaries
     *
     * @param pkiOb {@link CBORValue} to parse
     * @return byte array containing DER-encoded value, if supported
     */
    public static byte[] extractDerEncodedPkiObject(CBORValue pkiOb) {
        if (pkiOb != null) {
            String encoding = pkiOb.getAsStringOrNull(COSEHeaderParameter.PKI_OB_ENCODING.cbor());
            if (Utils.isStringEmpty(encoding) || Utils.areStringsEqual(PKIEncoding.DER.getUri(), encoding)) {
                return pkiOb.getAsBytesOrNull(COSEHeaderParameter.PKI_OB_VAL.cbor());
            } else {
                LOG.warn("Unsupported encoding header value : '{}'", encoding);
            }
        }
        return null;
    }

    /**
     * Extract an {@code CRLRef} from 'CRLRef' CBOR object
     *
     * @param crlRefMap {@link CBORMap} representing the 'CRLRef' CBOR object
     * @return {@link CRLRef}
     * @deprecated since DSS 6.6. Use {@link #createCRLRef(CBORValue).}
     */
    @Deprecated
    public static CRLRef createCRLRef(CBORMap crlRefMap) {
        if (crlRefMap != null) {
            return createCRLRef(crlRefMap.toCBORValue());
        }
        return null;
    }

    /**
     * Extract an {@code CRLRef} from 'CRLRef' CBOR object
     *
     * @param crlRefMap {@link CBORValue} representing the 'CRLRef' CBOR object
     * @return {@link CRLRef}
     */
    public static CRLRef createCRLRef(CBORValue crlRefMap) {
        try {
            CBORValue digAlgVal = crlRefMap.getAsArrayOrNull(COSEHeaderParameter.CRL_REF_DIG_ALG_VAL.cbor());
            if (digAlgVal != null) {
                Digest digest = getDigestAlgAndVal(digAlgVal);
                if (digest != null) {
                    CBORValue crlId = crlRefMap.getAsMapOrNull(COSEHeaderParameter.CRL_REF_CRL_ID.cbor());
                    if (crlId != null) {
                        X500Principal issuer = getCRLIdIssuer(crlId);
                        Date crlIdIssueTime = getCRLIdIssueTime(crlId);
                        BigInteger crlIdNumber = getCRLIdNumber(crlId);
                        CRLRef crlRef = new CRLRef(digest, issuer, crlIdIssueTime, crlIdNumber);
                        crlRef.setCrlUri(getCRLIdUri(crlId));
                        return crlRef;
                    }
                }
            } else {
                LOG.warn("Mandatory header 'DigAlgVal' is missed within CRLRef. The entry is skipped.");
            }

        } catch (Exception e) {
            LOG.warn("Unable to extract a CRLRef. Reason : {}", e.getMessage(), e);
        }
        return null;
    }

    private static X500Principal getCRLIdIssuer(CBORValue crlId) {
        byte[] crlIdIssuer = crlId.getAsBytesOrNull(COSEHeaderParameter.CRL_ID_ISSUER.cbor());
        if (Utils.isArrayNotEmpty(crlIdIssuer)) {
            try {
                return DSSASN1Utils.toX500Principal(X500Name.getInstance(crlIdIssuer));
            } catch (Exception e) {
                LOG.warn("Unable to extract 'CRLId.issuer' header : {}", e.getMessage(), e);
            }
        }
        return null;
    }

    private static Date getCRLIdIssueTime(CBORValue crlId) {
        String crlIdIssueTime = crlId.getAsStringOrNull(COSEHeaderParameter.CRL_ID_ISSUE_TIME.cbor());
        if (crlIdIssueTime != null) {
            return CBORUtils.parseTDate(crlIdIssueTime);
        }
        return null;
    }

    private static BigInteger getCRLIdNumber(CBORValue crlId) {
        return crlId.getAsIntegerOrNull(COSEHeaderParameter.CRL_ID_NUMBER.cbor());
    }

    private static String getCRLIdUri(CBORValue crlId) {
        return crlId.getAsStringOrNull(COSEHeaderParameter.CRL_ID_URI.cbor());
    }

    /**
     * Extract an {@code OCSPRef} from 'OCSPRef' CBOR object
     *
     * @param ocspRefMap {@link CBORValue} representing the 'OCSPRef' CBOR object
     * @return {@link OCSPRef}
     */
    public static OCSPRef createOCSPRef(CBORValue ocspRefMap) {
        try {
            Digest digest;
            ResponderId responderId;
            Date producedAt;

            CBORValue digAlgVal = ocspRefMap.getAsArrayOrNull(COSEHeaderParameter.OCSP_REF_DIG_ALG_VAL.cbor());
            if (digAlgVal != null) {
                digest = getDigestAlgAndVal(digAlgVal);
            } else {
                LOG.warn("Mandatory header 'DigAlgVal' is missed within 'OCSPRef'. The entry is skipped.");
                return null;
            }

            CBORValue ocspId = ocspRefMap.getAsMapOrNull(COSEHeaderParameter.OCSP_REF_OCSP_ID.cbor());
            if (ocspId != null) {
                responderId = getResponderId(ocspId);
                producedAt = getProducedAt(ocspId);
            } else {
                LOG.warn("Mandatory header 'ocspId' is missed within 'OCSPRef'. The entry is skipped.");
                return null;
            }

            if (digest != null && responderId != null && producedAt != null) {
                OCSPRef ocspRef = new OCSPRef(digest, producedAt, responderId);
                ocspRef.setUri(getOCSPIdUri(ocspId));
                return ocspRef;
            }

        } catch (Exception e) {
            LOG.warn("Unable to extract a CRLRef. Reason : {}", e.getMessage(), e);
        }
        return null;
    }

    private static ResponderId getResponderId(CBORValue ocspId) {
        CBORValue responderIdMap = ocspId.getAsMapOrNull(COSEHeaderParameter.OCSP_ID_RESPONDER_ID_CHOICE.cbor());
        if (responderIdMap != null && responderIdMap.size() != 0) {
            X500Principal subjectX500Principal = null;
            byte[] ski = null;

            byte[] responderIdByName = ocspId.getAsBytesOrNull(COSEHeaderParameter.RESPONDER_ID_CHOICE_RESPONDER_ID_BY_NAME.cbor());
            if (Utils.isArrayNotEmpty(responderIdByName)) {
                subjectX500Principal = DSSASN1Utils.toX500Principal(X500Name.getInstance(responderIdByName));
            }

            byte[] responderIdByKey = ocspId.getAsBytesOrNull(COSEHeaderParameter.RESPONDER_ID_CHOICE_RESPONDER_ID_BY_KEY.cbor());
            if (Utils.isArrayNotEmpty(responderIdByKey)) {
                ski = responderIdByKey;
            }

            if (subjectX500Principal != null || Utils.isArrayNotEmpty(ski)) {
                return new ResponderId(subjectX500Principal, ski);
            } else {
                LOG.warn("Fields 'responderIdByName' and 'responderIdByKey' shall be present within a 'ResponderIdChoice' header!");
            }
        }
        return null;
    }

    private static Date getProducedAt(CBORValue ocspId) {
        String ocspIdProducedAt = ocspId.getAsStringOrNull(COSEHeaderParameter.OCSP_ID_PRODUCED_AT.cbor());
        if (ocspIdProducedAt != null) {
            return CBORUtils.parseTDate(ocspIdProducedAt);
        } else {
            LOG.warn("Field 'producedAt' shall be present within a 'OCSPId' CBOR Map!");
        }
        return null;
    }

    private static String getOCSPIdUri(CBORValue ocspId) {
        return ocspId.getAsStringOrNull(COSEHeaderParameter.OCSP_ID_URI.cbor());
    }

    /**
     * Builds a list of counter signatures from the given {@code uHeader} embedded in a {@code CBAdESSignature}
     *
     * @param signature {@link CBAdESSignature} master signature
     * @param uHeader {@link CBAdESUHeadersComponent}
     * @return a list of {@link CBAdESSignature}s
     */
    public static List<CBAdESSignature> buildCounterSignatures(CBAdESSignature signature, CBAdESUHeadersComponent uHeader) {
        List<CBAdESSignature> counterSignatures = buildCounterSignatures(signature, uHeader.getHeaderId(), uHeader.getValue(), false);
        if (Utils.isCollectionNotEmpty(counterSignatures)) {
            for (CBAdESSignature counterSignature : counterSignatures) {
                counterSignature.setMasterCounterSignatureComponent(uHeader);
            }
        }
        return counterSignatures;
    }

    /**
     * Builds counter signatures from a CBORObject value with the given {@code headerKey}
     *
     * @param signature {@link CBAdESSignature} master signature
     * @param headerKey {@link CBORValue} key of the header embedding the counter signature
     * @param headerValue {@link CBORValue} the header value encapsulating the counter signature
     * @param bodyStructure TRUE if the counter signature has been extracted from the body structure (for COSE_SIGN), FALSE otherwise
     * @return a list of {@link CBAdESSignature}s
     * @deprecated since DSS 6.6. Use {@link #buildCounterSignatures(CBAdESSignature, CBORValue, CBORValue, boolean)} instead.
     */
    @Deprecated
    public static List<CBAdESSignature> buildCounterSignatures(CBAdESSignature signature, CBORObject headerKey,
                                                               CBORObject headerValue, boolean bodyStructure) {
        return buildCounterSignatures(signature, headerKey.toCBORValue(), headerValue.toCBORValue(), bodyStructure);
    }

    /**
     * Builds counter signatures from a CBORObject value with the given {@code headerKey}
     *
     * @param signature {@link CBAdESSignature} master signature
     * @param headerKey {@link CBORValue} key of the header embedding the counter signature
     * @param headerValue {@link CBORValue} the header value encapsulating the counter signature
     * @param bodyStructure TRUE if the counter signature has been extracted from the body structure (for COSE_SIGN), FALSE otherwise
     * @return a list of {@link CBAdESSignature}s
     */
    public static List<CBAdESSignature> buildCounterSignatures(CBAdESSignature signature, CBORValue headerKey,
                                                               CBORValue headerValue, boolean bodyStructure) {
        if (!headerKey.isUnsignedInteger()) {
            return Collections.emptyList(); // unknown
        }
        COSESignatureType counterSignatureContext = COSESignatureType.getCounterSignatureContextByHeaderKey(headerKey.asInteger().longValue());
        // is known
        if (counterSignatureContext != null) {
            final List<CBAdESSignature> result = new ArrayList<>();

            COSEStructure masterSignatureStructure = getMasterSignatureStructure(signature.getCoseSignature(), bodyStructure);
            COSECounterSignStructure coseCounterSignStructure = COSECounterSignatureParser.fromCBORValue(headerValue)
                    .setContext(counterSignatureContext)
                    .setMasterSignature(masterSignatureStructure)
                    .parse();
            List<CBORSignature> coseSignatures = CBORSignature.fromCOSECounterSignStructure(coseCounterSignStructure);
            for (CBORSignature coseSignature : coseSignatures) {
                CBAdESSignature cbadesCounterSignature = new CBAdESSignature(coseSignature);
                cbadesCounterSignature.setFilename(signature.getFilename());
                cbadesCounterSignature.setMasterSignature(signature);
                if (coseSignature.getExternallySuppliedData() != null) {
                    cbadesCounterSignature.getCoseSignature().setExternalAttributes(coseSignature.getExternallySuppliedData());
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("A COSE counter signature found with Id : '{}'", cbadesCounterSignature.getId());
                }
                // only COSE_Sign1 covers master signature's payload
                if (COSESignatureType.COSE_SIGN1 == signature.getCOSESignatureType() && signature.isDetachedSignature()) {
                    signature.checkSignatureIntegrity(); // ensure payload
                    coseSignature.setPayload(signature.getCoseSignature().getPayload());
                }
                result.add(cbadesCounterSignature);
            }
            return result;
        }
        return Collections.emptyList();
    }

    private static COSEStructure getMasterSignatureStructure(CBORSignature cose, boolean bodyStructure) {
        switch (cose.getContext()) {
            case COSE_SIGN:
                return bodyStructure ? cose.getCoseSignStructure() : cose.getSignerSignature();
            case COSE_SIGN1:
                return cose.getCoseSignStructure();
            default:
                // counter signatures
                return cose.getSignerSignature();
        }
    }

    /**
     * Validates COSE signature against the CB-AdES CDDL definition
     *
     * @param cose {@link CBORSignature} to be validated
     * @return a list of errors if validation fails, empty list if succeeds
     */
    public static List<String> validateAgainstCBAdESSchema(CBORSignature cose) {
        COSEStructure coseStructure = cose.getSignerSignature() != null ? cose.getSignerSignature() : cose.getCoseSignStructure();
        if (cose.getContext().isCounterSignature() || cose.getContext().isCounterSignatureV2()) {
            return CBAdESSchemaUtils.getInstance().validateAgainstSchema(coseStructure.toCBORValue(), CBAdESSchemaUtils.COSE_COUNTER_SIGNATURE);
        }
        return CBAdESSchemaUtils.getInstance().validateAgainstSchema(coseStructure.toCBORValue(), CBAdESSchemaUtils.COSE_MESSAGES);
    }

}
