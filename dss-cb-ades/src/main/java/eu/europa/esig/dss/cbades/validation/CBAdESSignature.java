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
package eu.europa.esig.dss.cbades.validation;

import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.CBAdESSignatureIntegrityValidator;
import eu.europa.esig.dss.cbades.CBAdESUtils;
import eu.europa.esig.dss.cbades.COSEConstants;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.COSEStructure;
import eu.europa.esig.dss.cbades.COSEUnprotectedHeader;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.cbor.CBORValueFactory;
import eu.europa.esig.dss.cbades.cwt.CWTClaims;
import eu.europa.esig.dss.cbades.validation.scope.CBAdESSignatureScopeFinder;
import eu.europa.esig.dss.cbades.validation.timestamp.CBAdESTimestampSource;
import eu.europa.esig.dss.enumerations.COSESignatureType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EndorsementType;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.model.UserNotice;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.model.signature.CommitmentTypeIndication;
import eu.europa.esig.dss.model.signature.SignatureCryptographicVerification;
import eu.europa.esig.dss.model.signature.SignatureDigestReference;
import eu.europa.esig.dss.model.signature.SignaturePolicy;
import eu.europa.esig.dss.model.signature.SignatureProductionPlace;
import eu.europa.esig.dss.model.signature.SignerRole;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.signature.DefaultAdvancedSignature;
import eu.europa.esig.dss.spi.signature.identifier.SignatureIdentifierBuilder;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.CandidatesForSigningCertificate;
import eu.europa.esig.dss.spi.x509.CertificateValidity;
import eu.europa.esig.dss.spi.x509.SignatureIntegrityValidator;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Represents an implementation of a CB-AdES ETSI TS 119 152-1 signature
 *
 */
public class CBAdESSignature extends DefaultAdvancedSignature {

    private static final long serialVersionUID = 3946729148011406453L;

    private static final Logger LOG = LoggerFactory.getLogger(CBAdESSignature.class);

    /** The COSE signature object */
    private final CBORSignature cose;

    /** The list of unsigned properties embedded into the 'uHeaders' array */
    private CBAdESUHeaders uHeaders;

    /** Defines if the validating signature is detached */
    private final boolean isDetached;

    /**
     * The counter signature component embedding the current signature
     * NOTE: used for counter signatures only
     */
    private CBAdESUHeadersComponent masterCounterSignatureComponent;

    /**
     * Default constructor
     *
     * @param cose {@link CBORSignature}
     */
    public CBAdESSignature(CBORSignature cose) {
        this.cose = cose;
        this.isDetached = cose.getPayload() == null || cose.getPayload().isNull();
    }

    /**
     * Sets externally supplied data as per RFC 9052 "4.3. Externally Supplied Data".
     * This is an optional protected element of COSE signatures.
     *
     * @param externallySuppliedData {@link DSSDocument}
     */
    public void setExternallySuppliedData(DSSDocument externallySuppliedData) {
        if (externallySuppliedData != null) {
            cose.setExternalAttributesBytes(DSSUtils.toByteArray(externallySuppliedData));
        } else {
            cose.setExternalAttributesBytes(null);
        }
    }

    /**
     * Returns the corresponding {@link CBORSignature} object
     *
     * @return {@link CBORSignature}
     */
    public CBORSignature getCoseSignature() {
        return cose;
    }

    /**
     * Gets context of the COSE signature
     *
     * @return {@link COSESignatureType}
     */
    public COSESignatureType getCOSESignatureType() {
        return cose.getContext();
    }

    /**
     * Gets whether the COSE signature structure is tagged
     *
     * @return whether the COSE signature structure is tagged
     */
    public boolean isTagged() {
        return cose.isTagged();
    }

    @Override
    public SignatureForm getSignatureForm() {
        return SignatureForm.CBAdES;
    }

    @Override
    public SignatureCertificateSource getCertificateSource() {
        if (offlineCertificateSource == null) {
            offlineCertificateSource = new CBAdESCertificateSource(cose, getUHeaders());
        }
        return offlineCertificateSource;
    }

    @Override
    public OfflineCRLSource getCRLSource() {
        if (signatureCRLSource == null) {
            signatureCRLSource = new CBAdESCRLSource(getUHeaders());
        }
        return signatureCRLSource;
    }

    @Override
    public OfflineOCSPSource getOCSPSource() {
        if (signatureOCSPSource == null) {
            signatureOCSPSource = new CBAdESOCSPSource(getUHeaders());
        }
        return signatureOCSPSource;
    }

    @Override
    public CBAdESTimestampSource getTimestampSource() {
        if (signatureTimestampSource == null) {
            signatureTimestampSource = new CBAdESTimestampSource(this);
        }
        return (CBAdESTimestampSource) signatureTimestampSource;
    }

    /**
     * Returns unsigned properties embedded into the 'uHeaders' array
     *
     * @return {@link CBAdESUHeaders}
     */
    public CBAdESUHeaders getUHeaders() {
        if (uHeaders == null) {
            uHeaders = new CBAdESUHeaders(cose);
        }
        return uHeaders;
    }

    /**
     * Gets a counter signature component embedding the current signature
     *
     * @return {@link CBAdESUHeadersComponent} 'cSig' embedding the current signature
     */
    public CBAdESUHeadersComponent getMasterCounterSignatureComponent() {
        return masterCounterSignatureComponent;
    }

    /**
     * Sets a 'cSig' component embedding the current signature
     *
     * @param masterCounterSignatureComponent {@link CBAdESUHeadersComponent} 'cSig' embedding the current signature
     */
    public void setMasterCounterSignatureComponent(CBAdESUHeadersComponent masterCounterSignatureComponent) {
        this.masterCounterSignatureComponent = masterCounterSignatureComponent;
    }

    @Override
    public SignatureAlgorithm getSignatureAlgorithm() {
        return cose.getAlgorithm();
    }

    @Override
    public Date getSigningTime() {
        CBORValue cwtClaims = cose.getProtectedHeaderValueAsMap(COSEHeaderParameter.CWT_CLAIMS.cbor());
        if (cwtClaims != null && cwtClaims.size() != 0) {
            CBORValue iatHeader = cwtClaims.get(CWTClaims.IAT.cbor());
            return CBORUtils.fromNumericDate(iatHeader);
        }
        LOG.debug("Unable to extract claimed signing-time: No 'CWT Claims enclosing the iat' header was found.");
        return null;
    }

    @Override
    public String getContentType() {
        // not applicable (see JAdES)
        return null;
    }

    @Override
    public String getMimeType() {
        /*
         * content type: This header parameter is used to indicate the content
         * type of the data in the "payload" or "ciphertext" field.  Integers
         * are from the "CoAP Content-Formats" IANA registry table
         * [COAP.Formats]. Text values follow the syntax of "<type-
         * name>/<subtype-name>", where <type-name> and <subtype-name> are
         * defined in Section 4.2 of [RFC6838].
         */
        String value = null;
        CBORValue cty = cose.getProtectedHeaderValue(COSEHeaderParameter.CONTENT_TYPE.cbor());
        if (cty != null) {
            if (cty.isTextString()) {
                value = cty.asString();
            } else if (cty.isUnsignedInteger()) {
                value = String.valueOf(cty.asInteger());
            } else {
                LOG.warn("'content type' protected header shall be either if String or Unsigned Integer type!");
            }
        }
        if (Utils.isStringEmpty(value)) {
            // sigD: return the first one when present
            List<String> ctys = getSignedDataContentTypeList();
            if (Utils.isCollectionNotEmpty(ctys)) {
                value = ctys.get(0);
            }
        }
        return value;
    }

    @Override
    public String getSignatureType() {
        CBORValue typ = cose.getProtectedHeaderValue(COSEHeaderParameter.SIGNATURE_TYPE.cbor());
        if (typ != null) {
            if (typ.isTextString()) {
                return typ.asString();
            } else if (typ.isUnsignedInteger()) {
                return String.valueOf(typ.asInteger());
            } else {
                LOG.warn("'signature type' protected header shall be either if String or Unsigned Integer type!");
            }
        }
        return null;
    }

    @Override
    public SignatureProductionPlace getSignatureProductionPlace() {
        CBORValue sigPl = cose.getProtectedHeaderValueAsMap(COSEHeaderParameter.SIG_PL.cbor());
        if (sigPl != null && sigPl.size() != 0) {
            SignatureProductionPlace result = new SignatureProductionPlace();
            result.setCountryName(sigPl.getAsStringOrNull(COSEHeaderParameter.SIG_PL_ADDRESS_COUNTRY.cbor()));
            result.setCity(sigPl.getAsStringOrNull(COSEHeaderParameter.SIG_PL_ADDRESS_LOCALITY.cbor()));
            result.setStateOrProvince(sigPl.getAsStringOrNull(COSEHeaderParameter.SIG_PL_ADDRESS_REGION.cbor()));
            result.setPostOfficeBoxNumber(sigPl.getAsStringOrNull(COSEHeaderParameter.SIG_PL_POST_OFFICE_BOX_NUMBER.cbor()));
            result.setPostalCode(sigPl.getAsStringOrNull(COSEHeaderParameter.SIG_PL_POSTAL_CODE.cbor()));
            result.setStreetAddress(sigPl.getAsStringOrNull(COSEHeaderParameter.SIG_PL_STREET_ADDRESS.cbor()));
            return result;
        }
        return null;
    }

    @Override
    public List<CommitmentTypeIndication> getCommitmentTypeIndications() {
        List<CommitmentTypeIndication> result = new ArrayList<>();
        CBORValue srCms = cose.getProtectedHeaderValueAsArray(COSEHeaderParameter.SR_CMS.cbor());
        if (srCms != null && srCms.size() != 0) {
            for (CBORValue srCm : srCms.getElements()) {
                if (!srCm.isMap()) {
                    LOG.warn("Item of 'srCms' protected header shall be a type of CBOR Map! Found object of class : {}",
                            srCm.getClass().getSimpleName());
                    continue;
                }
                if (srCm.size() != 0) {
                    CBORValue commId = srCm.getAsMapOrNull(COSEHeaderParameter.SR_CM_COMM_ID.cbor());
                    if (commId != null && commId.size() != 0) {
                        String oid = CBORUtils.fromUri(commId.get(COSEHeaderParameter.OID_ID.cbor()));
                        oid = DSSUtils.getObjectIdentifierValue(oid);
                        if (Utils.isStringNotBlank(oid)) {
                            CommitmentTypeIndication commitmentTypeIndication = new CommitmentTypeIndication(oid);
                            String desc = commId.getAsStringOrNull(COSEHeaderParameter.OID_DESC.cbor());
                            commitmentTypeIndication.setDescription(desc);
                            CBORValue docRefs = commId.getAsArrayOrNull(COSEHeaderParameter.OID_DOC_REFS.cbor());
                            commitmentTypeIndication.setDocumentReferences(toListOfUriStrings(docRefs));
                            result.add(commitmentTypeIndication);

                        } else {
                            LOG.warn("Id parameter in the OID is not conformant! The entry is skipped.");
                        }
                    }
                }
            }
        }
        return result;
    }

    @Override
    public List<SignerRole> getCertifiedSignerRoles() {
        List<SignerRole> result = new ArrayList<>();
        CBORValue srAts = getSignerAttributes();
        if (srAts != null && srAts.size() != 0) {
            CBORValue certifiedAttrs = srAts.getAsArrayOrNull(COSEHeaderParameter.SR_ATS_CERTIFIED_ATTRS.cbor());
            if (certifiedAttrs != null && certifiedAttrs.size() != 0) {
                for (CBORValue certifiedItem : certifiedAttrs.getElements()) {
                    String certifiedVal = getCertifiedVal(certifiedItem);
                    if (Utils.isStringNotEmpty(certifiedVal)) {
                        result.add(new SignerRole(certifiedVal, EndorsementType.CERTIFIED));
                    }
                }
            }
        }
        return result;
    }

    private String getCertifiedVal(CBORValue certifiedItem) {
        if (!certifiedItem.isMap()) {
            LOG.warn("Item of a 'certifiedAttrs' shall be of type CBOR Map. Found type : {}", certifiedItem.getClass().getSimpleName());
            return null;
        }

        CBORValue x509AttrCert = certifiedItem.getAsMapOrNull(COSEHeaderParameter.CERTIFIED_ATTR_X509_ATTR_CERT.cbor());
        if (x509AttrCert != null && x509AttrCert.size() != 0) {
            byte[] pkiObVal = x509AttrCert.getAsBytesOrNull(COSEHeaderParameter.PKI_OB_VAL.cbor());
            if (pkiObVal != null) {
                // TODO : support other encodings ?
                // DER encoding by default -> return b64
                return Utils.toBase64(pkiObVal);
            }
        }

        CBORValue otherAttrCert = certifiedItem.getAsMapOrNull(COSEHeaderParameter.CERTIFIED_ATTR_OTHER_ATTR_CERT.cbor());
        if (otherAttrCert != null && otherAttrCert.size() != 0) {
            LOG.warn("Unsupported 'otherAttrCert' type found.");
            return null;
        }

        LOG.warn("One of types 'x509AttrCert' or 'otherAttrCert' is expected in 'CertifiedAttr'.");
        return null;
    }

    @Override
    public List<SignerRole> getClaimedSignerRoles() {
        CBORValue srAts = getSignerAttributes();
        if (srAts != null && srAts.size() != 0) {
            CBORValue claimed = srAts.getAsArrayOrNull(COSEHeaderParameter.SR_ATS_CLAIMED.cbor());
            if (claimed != null && claimed.size() != 0) {
                return getSignerRoles(claimed, EndorsementType.CLAIMED);
            }
        }
        return Collections.emptyList();
    }

    @Override
    public List<SignerRole> getSignedAssertions() {
        CBORValue srAts = getSignerAttributes();
        if (srAts != null && srAts.size() != 0) {
            CBORValue signedAssertions = srAts.getAsArrayOrNull(COSEHeaderParameter.SR_ATS_SIGNED_ASSERTIONS.cbor());
            if (signedAssertions != null && signedAssertions.size() != 0) {
                return getSignerRoles(signedAssertions, EndorsementType.SIGNED);
            }
        }
        return Collections.emptyList();
    }

    private List<SignerRole> getSignerRoles(CBORValue attrArrays, EndorsementType category) {
        final List<SignerRole> result = new ArrayList<>();
        if (attrArrays != null && attrArrays.size() != 0) {
            /*
             * NotCertifiedItem = [
             * 	mediaType : tstr,	;String identifying the type of claimed attributes or signed assertions
             * 	encoding : tstr,	;String identifying the encoding of claimed attributes or signed assertions
             * 	qVals : [+any]	;Array with the claimed attributes or signed assertions
             * ]
             */
            for (CBORValue notCertifiedItem : attrArrays.getElements()) {
                try {
                    if (!notCertifiedItem.isArray()) {
                        LOG.warn("'NotCertifiedItem' item of 'AttrArrays' CBOR array shall be of CBOR Array type.");
                        continue;
                    }
                    CBORValue qVals = notCertifiedItem.getAsArrayOrNull(COSEConstants.NOT_CERTIFIED_ITEM_QVALS);
                    if (qVals != null) {
                        for (CBORValue val : qVals.getElements()) {
                            if (val.isTextString()) {
                                result.add(new SignerRole(val.asString(), category));
                            } else if (val.isByteString()) {
                                LOG.debug("Item of 'qVals' array is of ByteString type found. Return base64-encoded value.");
                                result.add(new SignerRole(Utils.toBase64(val.asBytes()), category));
                            } else if (val.isNegativeInteger() || val.isUnsignedInteger()) {
                                LOG.debug("Item of 'qVals' array is of NegativeInteger or UnsignedInteger type found. " +
                                        "Convert to String value.");
                                result.add(new SignerRole(String.valueOf(val.asInteger()), category));
                            } else {
                                LOG.warn("Unsupported type of item from 'qVals' array : {}", val.getClass().getSimpleName());
                            }
                        }
                    } else {
                        LOG.warn("Unable to extract 'qVals'. Shall be a CBOR Array at the position '{}' " +
                                "of a 'NotCertifiedItem' object.", COSEConstants.NOT_CERTIFIED_ITEM_QVALS);
                    }

                } catch (Exception e) {
                    String errorMessage = "An error occurred on 'attrArrays' processing : {}";
                    if (LOG.isDebugEnabled()) {
                        LOG.warn(errorMessage, e.getMessage(), e);
                    } else {
                        LOG.warn(errorMessage, e.getMessage());
                    }
                }

            }
        }
        return result;
    }

    private CBORValue getSignerAttributes() {
        return cose.getProtectedHeaderValueAsMap(COSEHeaderParameter.SR_ATS.cbor());
    }

    @Override
    protected SignaturePolicy buildSignaturePolicy() {
        CBORValue sigPId = cose.getProtectedHeaderValueAsMap(COSEHeaderParameter.SIG_PID.cbor());
        if (sigPId != null && sigPId.size() != 0) {
            CBORValue sigPOid = sigPId.getAsMapOrNull(COSEHeaderParameter.SIG_P_ID_ID.cbor());
            if (sigPOid != null && sigPOid.size() != 0) {
                String oid = CBORUtils.fromUri(sigPOid.get(COSEHeaderParameter.OID_ID.cbor()));
                oid = DSSUtils.getObjectIdentifierValue(oid);
                if (Utils.isStringNotBlank(oid)) {
                    signaturePolicy = new SignaturePolicy(oid);
                    String desc = sigPOid.getAsStringOrNull(COSEHeaderParameter.OID_DESC.cbor());
                    signaturePolicy.setDescription(desc);
                    CBORValue docRefs = sigPOid.getAsArrayOrNull(COSEHeaderParameter.OID_DOC_REFS.cbor());
                    signaturePolicy.setDocumentationReferences(toListOfUriStrings(docRefs));

                } else {
                    LOG.warn("Id parameter in the OID with the value '{}' is not conformant! " +
                            "The 'sigPId' entry cannot be extracted.", oid);
                    return null;
                }

                CBORValue digAlgVal = sigPId.getAsArrayOrNull(COSEHeaderParameter.SIG_P_ID_DIG_ALG_VAL.cbor());
                signaturePolicy.setDigest(CBAdESUtils.getDigestAlgAndVal(digAlgVal));

                Boolean digPSp = sigPId.getAsBooleanOrNull(COSEHeaderParameter.SIG_P_ID_DIG_P_SP.cbor());
                if (digPSp != null) {
                    signaturePolicy.setHashAsInTechnicalSpecification(digPSp);
                }

                CBORValue qualifiers = sigPId.getAsArrayOrNull(COSEHeaderParameter.SIG_P_ID_SIG_P_QUALS.cbor());
                if (qualifiers != null && qualifiers.size() != 0) {
                    signaturePolicy.setUri(getSPUri(qualifiers));
                    signaturePolicy.setUserNotice(getSPUserNotice(qualifiers));
                    signaturePolicy.setDocSpecification(getSPDSpec(qualifiers));
                }
            }

        }
        return signaturePolicy;
    }

    private List<String> toListOfStrings(CBORValue cborArray) {
        if (cborArray != null && cborArray.size() != 0) {
            final List<String> computedList = new ArrayList<>();
            for (CBORValue arrayItem : cborArray.getElements()) {
                if (arrayItem.isTextString()) {
                    computedList.add(arrayItem.asString());
                }
            }
            return computedList;
        }
        return Collections.emptyList();
    }

    private List<String> toListOfUriStrings(CBORValue cborArray) {
        if (cborArray != null && cborArray.size() != 0) {
            final List<String> computedList = new ArrayList<>();
            for (CBORValue arrayItem : cborArray.getElements()) {
                String uri = CBORUtils.fromUri(arrayItem);
                if (Utils.isStringNotEmpty(uri)) {
                    computedList.add(uri);
                }
            }
            return computedList;
        }
        return Collections.emptyList();
    }

    private String getSPUri(CBORValue qualifiers) {
        String spUri = null;
        for (CBORValue qualifier : qualifiers.getElements()) {
            if (!qualifier.isMap()) {
                LOG.warn("Item of 'sigPQuals' array shall be of type CBOR Map.");
                continue;
            }
            if (qualifier.size() != 0) {
                String spUriStr = CBORUtils.fromUri(qualifier.get(COSEHeaderParameter.SIG_P_QUAL_SP_URI.cbor()));
                if (Utils.isStringNotEmpty(spUriStr)) {
                    if (spUri == null) {
                        spUri = spUriStr;
                    } else {
                        LOG.warn("Multiple 'spUri' qualifiers found. Only one entry is supported by the current implementation");
                    }
                }
            }
        }
        return spUri;
    }

    private UserNotice getSPUserNotice(CBORValue qualifiers) {
        UserNotice userNotice = null;
        for (CBORValue qualifier : qualifiers.getElements()) {
            if (!qualifier.isMap()) {
                // warn is logged before
                continue;
            }
            CBORValue spUserNotice = qualifier.getAsMapOrNull(COSEHeaderParameter.SIG_P_QUAL_SP_USER_NOTICE.cbor());
            if (spUserNotice != null && spUserNotice.size() != 0) {
                if (userNotice != null) {
                    LOG.warn("Multiple 'spUserNotice' qualifiers found. Only one entry is supported by the current implementation");
                    continue;
                }

                try {
                    userNotice = new UserNotice();

                    CBORValue noticeRef = spUserNotice.getAsMapOrNull(COSEHeaderParameter.SP_USER_NOTICE_NOTICE_REF.cbor());
                    if (noticeRef != null && noticeRef.size() != 0) {
                        final String organization = noticeRef.getAsStringOrNull(COSEHeaderParameter.NOTICE_REF_ORG.cbor());
                        if (Utils.isStringNotBlank(organization)) {
                            userNotice.setOrganization(organization);
                        }

                        final CBORValue noticeNumbers = noticeRef.getAsArrayOrNull(COSEHeaderParameter.NOTICE_REF_NOTICE_NUMBERS.cbor());
                        if (noticeNumbers != null && noticeNumbers.size() != 0) {
                            userNotice.setNoticeNumbers(noticeNumbers.getElements().stream()
                                    .filter(CBORValue::isInteger).map(CBORValue::asInteger)
                                    .mapToInt(BigInteger::intValue).toArray());
                        }
                    }
                    final String explTest = spUserNotice.getAsStringOrNull(COSEHeaderParameter.SP_USER_NOTICE_EXPL_TEXT.cbor());
                    if (Utils.isStringNotBlank(explTest)) {
                        userNotice.setExplicitText(explTest);
                    }

                } catch (Exception e) {
                    String errorMessage = "Unable to build SPUserNotice qualifier. Reason : {}";
                    if (LOG.isDebugEnabled()) {
                        LOG.warn(errorMessage, e.getMessage(), e);
                    } else {
                        LOG.warn(errorMessage, e.getMessage());
                    }
                }
            }
        }
        return userNotice;
    }

    private SpDocSpecification getSPDSpec(CBORValue qualifiers) {
        SpDocSpecification spDocSpecification = null;
        for (CBORValue qualifier : qualifiers.getElements()) {
            if (!qualifier.isMap()) {
                // warn is logged before
                continue;
            }
            CBORValue spDSpec = qualifier.getAsMapOrNull(COSEHeaderParameter.SIG_P_QUAL_SP_D_SPEC.cbor());
            if (spDSpec != null && spDSpec.size() != 0) {
                if (spDocSpecification != null) {
                    LOG.warn("Multiple 'spDSpec' qualifiers found. Only one entry is supported by the current implementation");
                    continue;
                }

                String oid = CBORUtils.fromUri(spDSpec.get(COSEHeaderParameter.OID_ID.cbor()));
                oid = DSSUtils.getObjectIdentifierValue(oid);
                if (Utils.isStringNotBlank(oid)) {
                    spDocSpecification = new SpDocSpecification();
                    spDocSpecification.setId(oid);
                    String desc = spDSpec.getAsStringOrNull(COSEHeaderParameter.OID_DESC.cbor());
                    spDocSpecification.setDescription(desc);
                    CBORValue docRefs = spDSpec.getAsArrayOrNull(COSEHeaderParameter.OID_DOC_REFS.cbor());
                    spDocSpecification.setDocumentationReferences(toListOfUriStrings(docRefs).toArray(new String[] {}));

                } else {
                    LOG.warn("Id parameter in the OID with the value '{}' is not conformant! " +
                            "The 'spDSpec' qualifier cannot be extracted.", oid);
                    return null;
                }
            }
        }
        return spDocSpecification;
    }

    /**
     * Checks if the CB-AdES Signature is detached (payload is not present within the signature structure)
     *
     * @return TRUE if the signature is detached, FALSE otherwise
     */
    public boolean isDetachedSignature() {
        return isDetached && !isCounterSignature();
    }

    /**
     * Returns a mechanism used in 'sigD' to cover a detached content
     *
     * @return {@link SigDMechanism}
     */
    public SigDMechanism getSigDMechanism() {
        CBORValue sigD = cose.getProtectedHeaderValueAsMap(COSEHeaderParameter.SIG_D.cbor());
        if (sigD != null && sigD.size() != 0) {
            String mechanismUri = CBORUtils.fromUri(sigD.get(COSEHeaderParameter.SIG_D_MID.cbor()));
            if (Utils.isStringNotEmpty(mechanismUri)) {
                SigDMechanism sigDMechanism = SigDMechanism.forCBAdESUri(mechanismUri);
                if (sigDMechanism == null) {
                    LOG.warn("The sigDMechanism with uri '{}' is not supported!", mechanismUri);
                }
                return sigDMechanism;
            } else {
                LOG.warn("No 'mId' field is found within 'sigD' protected header!");
            }
        }
        return null;
    }

    @Override
    public byte[] getSignatureValue() {
        return cose.getSignatureValue();
    }

    @Override
    protected SignatureDigestReference buildSignatureDigestReference(DigestAlgorithm digestAlgorithm) {
        // TODO : no definition is available -> build a signature structure based on its context
        COSEStructure coseSignStructure = COSESignatureType.COSE_SIGN1 == cose.getContext() ? cose.getCoseSignStructure() : cose.getSignerSignature();
        byte[] serializedBytes = coseSignStructure.serialize();
        byte[] digestValue = DSSUtils.digest(digestAlgorithm, serializedBytes);
        return new SignatureDigestReference(new Digest(digestAlgorithm, digestValue));
    }

    @Override
    public Digest getDataToBeSignedRepresentation() {
        List<ReferenceValidation> referenceValidations = getReferenceValidations();
        for (ReferenceValidation referenceValidation : referenceValidations) {
            if (DigestMatcherType.COSE_SIG_STRUCTURE.equals(referenceValidation.getType())) {
                return referenceValidation.isFound() ? referenceValidation.getDigest() : null;
            }
        }
        // shall not happen
        throw new DSSException("COSE_SIG_STRUCTURE is not found! Unable to compute DTBSR.");
    }

    @Override
    protected SignatureIdentifierBuilder getSignatureIdentifierBuilder() {
        return new CBAdESSignatureIdentifierBuilder(this);
    }

    @Override
    public void checkSignatureIntegrity() {

        if (signatureCryptographicVerification != null) {
            return;
        }

        signatureCryptographicVerification = new SignatureCryptographicVerification();

        boolean refsFound = false;
        boolean refsIntact = false;

        List<ReferenceValidation> referenceValidations = getReferenceValidations();

        if (Utils.isCollectionNotEmpty(referenceValidations)) {
            refsFound = true;
            refsIntact = true;

            for (ReferenceValidation referenceValidation : referenceValidations) {
                if (DigestMatcherType.COSE_SIG_STRUCTURE.equals(referenceValidation.getType())) {
                    signatureCryptographicVerification.setSignatureIntact(referenceValidation.isIntact());

                    for (String errorMessage : referenceValidation.getErrorMessages()) {
                        signatureCryptographicVerification.setErrorMessage(errorMessage);
                    }
                }
                refsFound = refsFound && referenceValidation.isFound();
                refsIntact = refsIntact && referenceValidation.isIntact();
            }
        }

        signatureCryptographicVerification.setReferenceDataFound(refsFound);
        signatureCryptographicVerification.setReferenceDataIntact(refsIntact);

    }

    @Override
    public List<ReferenceValidation> getReferenceValidations() {
        if (referenceValidations == null) {
            referenceValidations = new ArrayList<>();

            ReferenceValidation signingInputReferenceValidation = getSigningInputReferenceValidation();
            referenceValidations.add(signingInputReferenceValidation);

            if (isDetachedSignature()) {
                List<ReferenceValidation> detachedReferenceValidations = getDetachedReferenceValidations();
                if (Utils.isCollectionNotEmpty(detachedReferenceValidations)) {
                    referenceValidations.addAll(detachedReferenceValidations);
                }
            }

            if (isCounterSignature()) {
                referenceValidations.add(getCounterSignatureReferenceValidation());
            }

        }
        return referenceValidations;
    }

    private ReferenceValidation getSigningInputReferenceValidation() {
        ReferenceValidation signatureValueReferenceValidation = new ReferenceValidation();
        signatureValueReferenceValidation.setType(DigestMatcherType.COSE_SIG_STRUCTURE);

        try {
            try {
                SigDMechanism sigDMechanism = getSigDMechanism();
                boolean singleDetachedDocumentProvided = Utils.collectionSize(detachedContents) == 1;
                if (!isDetachedSignature()) {
                    // not detached
                    signatureValueReferenceValidation.setFound(true);

                } else if (sigDMechanism == null && singleDetachedDocumentProvided) {
                    // simple detached signature
                    byte[] payload = DSSUtils.toByteArray(detachedContents.get(0));
                    cose.setPayloadBytes(payload);
                    signatureValueReferenceValidation.setFound(true);

                } else if (SigDMechanism.OBJECT_ID_BY_URI.equals(sigDMechanism)) {
                    // detached with OBJECT_ID_BY_URI mechanism
                    byte[] payload = getPayloadForObjectIdByUriMechanism();
                    cose.setPayloadBytes(payload);
                    signatureValueReferenceValidation.setFound(payload != null);

                } else if (SigDMechanism.OBJECT_ID_BY_URI_HASH.equals(sigDMechanism)) {
                    // the sigD itself is signed with OBJECT_ID_BY_URI_HASH mechanism
                    signatureValueReferenceValidation.setFound(true);

                } else {
                    // otherwise original content is not found
                    LOG.warn("The payload is not found! The detached content must be provided!");
                }

            } catch (Exception e) {
                String errorMessage = "Unable to determine a JWS payload. Reason : {}";
                if (LOG.isDebugEnabled()) {
                    LOG.warn(errorMessage, e.getMessage(), e);
                } else {
                    LOG.warn(errorMessage, e.getMessage());
                }
            }

            SignatureAlgorithm signatureAlgorithm = getSignatureAlgorithm();
            if (signatureAlgorithm != null) {
                byte[] dataToSign = cose.getSignatureInputBytes();
                DigestAlgorithm digestAlgorithm = signatureAlgorithm.getDigestAlgorithm();
                Digest digest = new Digest(digestAlgorithm, DSSUtils.digest(digestAlgorithm, dataToSign));
                signatureValueReferenceValidation.setDigest(digest);

                CandidatesForSigningCertificate candidatesForSigningCertificate = getCandidatesForSigningCertificate();

                SignatureIntegrityValidator signingCertificateValidator = new CBAdESSignatureIntegrityValidator(cose);
                CertificateValidity certificateValidity = signingCertificateValidator.validate(candidatesForSigningCertificate);
                if (certificateValidity != null) {
                    candidatesForSigningCertificate.setTheCertificateValidity(certificateValidity);
                }

                List<String> errorMessages = signingCertificateValidator.getErrorMessages();
                signatureValueReferenceValidation.setErrorMessages(errorMessages);
                signatureValueReferenceValidation.setIntact(certificateValidity != null);
            }

        } catch (Exception e) {
            LOG.warn("The validation of signed input failed! Reason : {}", e.getMessage(), e);
        }

        return signatureValueReferenceValidation;
    }

    private byte[] getPayloadForObjectIdByUriMechanism() {
        if (Utils.isCollectionEmpty(detachedContents)) {
            throw new IllegalArgumentException("The detached contents shall be provided for validating a detached signature!");
        }

        List<DSSDocument> signedDocumentsByUri = getSignedDocumentsForObjectIdByUriMechanism();
        return CBAdESUtils.concatenateDSSDocuments(signedDocumentsByUri);
    }

    /**
     * This method returns a list of documents for ObjectIdByUrl or ObjectIdByUriHash mechanisms
     * Keeps the original order according to 'pars' dictionary content
     *
     * @return a list of {@link DSSDocument}s
     */
    public List<DSSDocument> getSignedDocumentsForObjectIdByUriMechanism() {
        List<String> signedDataUriList = getSignedDataUriList();
        List<DSSDocument> signedDocumentsByUri = Collections.emptyList();
        if (Utils.collectionSize(signedDataUriList) == 1 && Utils.collectionSize(detachedContents) == 1) {
            signedDocumentsByUri = Collections.singletonList(detachedContents.iterator().next());

        } else if (Utils.isCollectionNotEmpty(signedDataUriList)) {
            signedDocumentsByUri = new ArrayList<>();
            for (String signedDataName : signedDataUriList) {
                DSSDocument detachedDocumentByName = getDetachedDocumentByName(signedDataName, detachedContents);
                if (detachedDocumentByName != null) {
                    signedDocumentsByUri.add(detachedDocumentByName);
                } else {
                    throw new IllegalArgumentException(String.format(
                            "The detached content for a signed data with name '%s' has not been found!", signedDataName));
                }
            }
        }
        return signedDocumentsByUri;
    }

    private List<String> getSignedDataUriList() {
        CBORValue sigD = cose.getProtectedHeaderValueAsMap(COSEHeaderParameter.SIG_D.cbor());
        if (sigD != null && sigD.size() != 0) {
            CBORValue pars = sigD.getAsArrayOrNull(COSEHeaderParameter.SIG_D_PARS.cbor());
            if (pars != null && pars.size() != 0) {
                return toListOfStrings(pars);
            } else {
                LOG.warn("'pars' member of 'sigD' protected header shall be present and be of a CBOR Array type!");
            }
        }
        return Collections.emptyList();
    }

    private List<byte[]> getSignedDataHashList() {
        CBORValue sigD = cose.getProtectedHeaderValueAsMap(COSEHeaderParameter.SIG_D.cbor());
        if (sigD != null && sigD.size() != 0) {
            CBORValue hashV = sigD.getAsArrayOrNull(COSEHeaderParameter.SIG_D_HASH_V.cbor());
            if (hashV != null && hashV.size() != 0) {
                return hashV.getElements().stream().filter(CBORValue::isByteString)
                        .map(CBORValue::asBytes).collect(Collectors.toList());
            } else {
                LOG.warn("'hashV' member of 'sigD' protected header shall be present and be of a CBOR Array type!");
            }
        }
        return Collections.emptyList();
    }

    private List<String> getSignedDataContentTypeList() {
        CBORValue sigD = cose.getProtectedHeaderValueAsMap(COSEHeaderParameter.SIG_D.cbor());
        if (sigD != null && sigD.size() != 0) {
            CBORValue ctys = sigD.getAsArrayOrNull(COSEHeaderParameter.SIG_D_CTYS.cbor());
            if (ctys != null && ctys.size() != 0) {
                return toListOfStrings(ctys);
            } else {
                LOG.warn("'ctys' member of 'sigD' protected header shall be present and be of a CBOR Array type!");
            }
        }
        return Collections.emptyList();
    }

    private DSSDocument getDetachedDocumentByName(String documentName, List<DSSDocument> detachedContent) {
        documentName = DSSUtils.decodeURI(documentName);
        return DSSUtils.getDocumentWithName(detachedContent, documentName);
    }

    private List<ReferenceValidation> getDetachedReferenceValidations() {
        SigDMechanism sigDMechanism = getSigDMechanism();
        if (sigDMechanism != null) {
            switch (sigDMechanism) {
                case HTTP_HEADERS:
                case OBJECT_ID_BY_URI:
                    // the documents are added to the payload, not possible to extract separate reference validations
                    break;
                case OBJECT_ID_BY_URI_HASH:
                    return getReferenceValidationsByUriHashMechanism();
                default:
                    LOG.warn("The SigDMechanism '{}' is not supported!", sigDMechanism);
                    break;
            }
        }
        return Collections.emptyList();
    }

    private List<ReferenceValidation> getReferenceValidationsByUriHashMechanism() {
        List<DSSDocument> detachedDocuments = detachedContents;

        if (Utils.isCollectionEmpty(detachedContents)) {
            LOG.warn("The detached content is not provided! Validation of 'sigD' is not possible.");
            detachedDocuments = Collections.emptyList();
            // continue in order to extract signed data references
        }

        Map<String, byte[]> signedDataHashMap = getSignedDataUriHashMap();
        if (Utils.isMapEmpty(signedDataHashMap)) {
            LOG.warn("The SignedData has not been found or incorrect for detached content.");
            ReferenceValidation emptyReference = new ReferenceValidation();
            emptyReference.setType(DigestMatcherType.SIG_D_ENTRY);
            return Collections.singletonList(emptyReference);
        }

        DigestAlgorithm digestAlgorithm = getDigestAlgorithmForDetachedContent();
        if (digestAlgorithm == null) {
            LOG.warn("The DigestAlgorithm has not been found for the detached content.");
        }

        List<ReferenceValidation> detachedReferenceValidations = new ArrayList<>();

        for (Map.Entry<String, byte[]> signedDataEntry : signedDataHashMap.entrySet()) {
            ReferenceValidation referenceValidation = new ReferenceValidation();
            referenceValidation.setType(DigestMatcherType.SIG_D_ENTRY);

            String signedDataName = signedDataEntry.getKey();
            referenceValidation.setUri(signedDataName);

            byte[] expectedDigest = signedDataEntry.getValue();
            if (digestAlgorithm != null) {
                referenceValidation.setDigest(new Digest(digestAlgorithm, expectedDigest));
            }

            DSSDocument detachedDocument;
            if (Utils.collectionSize(signedDataHashMap.entrySet()) == 1 && Utils.collectionSize(detachedDocuments) == 1) {
                detachedDocument = detachedDocuments.iterator().next();
            } else {
                detachedDocument = getDetachedDocumentByDigest(digestAlgorithm, expectedDigest, detachedDocuments);
                if (detachedDocument == null) {
                    detachedDocument = getDetachedDocumentByName(signedDataName, detachedDocuments);
                }
            }

            if (detachedDocument != null) {
                referenceValidation.setFound(true);
                referenceValidation.setDocument(detachedDocument);
                if (digestAlgorithm != null && isDocumentDigestMatch(detachedDocument, digestAlgorithm, expectedDigest)) {
                    referenceValidation.setIntact(true);
                }
            } else {
                LOG.warn("A detached document for the 'sigD' header with name '{}' has not been found!", signedDataName);
            }

            detachedReferenceValidations.add(referenceValidation);
        }

        if (Utils.isCollectionEmpty(detachedReferenceValidations)) {
            // add an empty reference if none found
            ReferenceValidation referenceValidation = new ReferenceValidation();
            referenceValidation.setType(DigestMatcherType.SIG_D_ENTRY);
            detachedReferenceValidations.add(referenceValidation);
        }

        return detachedReferenceValidations;
    }

    private DSSDocument getDetachedDocumentByDigest(DigestAlgorithm digestAlgorithm, byte[] expectedDigest, List<DSSDocument> detachedContent) {
        if (digestAlgorithm == null || expectedDigest == null) {
            return null;
        }
        for (DSSDocument detachedDocument : detachedContent) {
            if (isDocumentDigestMatch(detachedDocument, digestAlgorithm, expectedDigest)) {
                return detachedDocument;
            }
        }
        return null;
    }

    private boolean isDocumentDigestMatch(DSSDocument detachedDocument, DigestAlgorithm digestAlgorithm, byte[] expectedDigest) {
        return Arrays.equals(expectedDigest, detachedDocument.getDigestValue(digestAlgorithm));
    }

    private Map<String, byte[]> getSignedDataUriHashMap() {
        Map<String, byte[]> signedDataHashMap = new LinkedHashMap<>(); // LinkedHashMap is used to keep the original order

        List<String> signedDataUriList = getSignedDataUriList();
        List<byte[]> signedDataHashList = getSignedDataHashList();
        if (signedDataUriList.size() != signedDataHashList.size()) {
            LOG.warn("The size of 'pars' and 'hashV' dictionaries does not match! See '5.2.9 The sigD header parameter'.");
            return signedDataHashMap;
        }

        for (int ii = 0; ii < signedDataUriList.size(); ii++) {
            signedDataHashMap.put(signedDataUriList.get(ii), signedDataHashList.get(ii));
        }
        return signedDataHashMap;
    }

    private DigestAlgorithm getDigestAlgorithmForDetachedContent() {
        CBORValue sigD = cose.getProtectedHeaderValueAsMap(COSEHeaderParameter.SIG_D.cbor());
        if (sigD != null && sigD.size() != 0) {
            BigInteger hashM = sigD.getAsIntegerOrNull(COSEHeaderParameter.SIG_D_HASH_M.cbor());
            if (hashM != null) {
                DigestAlgorithm digestAlgorithm = CBORUtils.getDigestAlgorithmForCoseId(hashM.longValue());
                if (digestAlgorithm != null) {
                    return digestAlgorithm;
                }
                LOG.warn("Not supported Digest Algorithm from 'sigD' protected header with Id : {}", hashM);

            } else {
                LOG.warn("'hashM' member of 'sigD' protected header shall be present for {} mechanism.",
                        SigDMechanism.OBJECT_ID_BY_URI_HASH.getCBAdESUri());
            }
        }
        return null;
    }

    private ReferenceValidation getCounterSignatureReferenceValidation() {
        ReferenceValidation referenceValidation = new ReferenceValidation();
        referenceValidation.setType(DigestMatcherType.COUNTER_SIGNED_SIGNATURE_VALUE);

        CBAdESSignature masterSignature = (CBAdESSignature) getMasterSignature();
        if (masterSignature != null) {

            byte[] signatureValue = masterSignature.getSignatureValue();
            if (Utils.isArrayNotEmpty(signatureValue)) {
                referenceValidation.setFound(true);
            }

            // signature value of the master signature can be embedded as a payload or other_fields,
            // depending on master signature type
            byte[] unverifiedBytes = cose.getOtherFieldsBytes();
            if (unverifiedBytes == null) {
                unverifiedBytes = cose.getPayloadBytes();
            }

            if (Utils.isArrayNotEmpty(unverifiedBytes)) {
                boolean intact = Arrays.equals(signatureValue, unverifiedBytes);
                if (!intact) {
                    LOG.warn("The payload of a countersignature with Id '{}' does not match the signature value of its master signature!",
                            getDSSId().asXmlId());
                }
                referenceValidation.setIntact(intact);
            } else {
                LOG.warn("No payload found for a countersignature with Id '{}'!", getDSSId().asXmlId());
                referenceValidation.setIntact(false);
            }
        }

        return referenceValidation;
    }

    /**
     * Returns a list of original documents signed by the signature
     *
     * @return a list of {@link DSSDocument}s
     */
    public List<DSSDocument> getOriginalDocuments() {
        if (isCounterSignature()) {
            final List<DSSDocument> originalDocuments = new ArrayList<>();
            CBAdESSignature masterSignature = (CBAdESSignature) getMasterSignature();
            originalDocuments.add(new InMemoryDocument(masterSignature.getSignatureValue()));
            if (COSESignatureType.COSE_SIGN1 == masterSignature.getCOSESignatureType()) {
                originalDocuments.addAll(masterSignature.getOriginalDocuments());
            }
            return originalDocuments;

        } else if (isDetachedSignature()) {

            List<DSSDocument> originalDocuments = new ArrayList<>();

            List<ReferenceValidation> referenceValidations = getReferenceValidations();
            for (ReferenceValidation referenceValidation : referenceValidations) {
                if (DigestMatcherType.SIG_D_ENTRY.equals(referenceValidation.getType()) && referenceValidation.isIntact()) {
                    String signedDataName = DSSUtils.decodeURI(referenceValidation.getUri());
                    DSSDocument detachedDocument = getDetachedDocumentByName(signedDataName, detachedContents);
                    if (detachedDocument != null) {
                        originalDocuments.add(detachedDocument);
                    }
                }
            }

            if (Utils.isCollectionEmpty(originalDocuments)) {
                // check if the signature of an old detached format
                SignatureCryptographicVerification signatureCryptographicVerification = getSignatureCryptographicVerification();
                if (signatureCryptographicVerification.isSignatureIntact()) {
                    if (isDetachedSignature() && Utils.collectionSize(detachedContents) == 1) {
                        return Collections.singletonList(detachedContents.get(0));
                    } else if (SigDMechanism.OBJECT_ID_BY_URI.equals(getSigDMechanism())) {
                        return getSignedDocumentsForObjectIdByUriMechanism();
                    }
                }
            }

            return originalDocuments;

        } else {
            byte[] payloadBytes = cose.getPayloadBytes();
            return Collections.singletonList(new InMemoryDocument(payloadBytes));
        }
    }

    @Override
    public SignatureLevel getDataFoundUpToLevel() {
        if (!hasAdESProfile()) {
            return SignatureLevel.CBOR_NOT_ETSI;
        }
        if (!hasBProfile()) {
            return SignatureLevel.CB_AdES;
        }
        if (!hasTProfile()) {
            return SignatureLevel.CB_AdES_BASELINE_B;
        }
        if (hasLTProfile()) {
            if (hasLTAProfile()) {
                return SignatureLevel.CB_AdES_BASELINE_LTA;
            }
            return SignatureLevel.CB_AdES_BASELINE_LT;
        }
        return SignatureLevel.CB_AdES_BASELINE_T;
    }

    @Override
    protected CBAdESBaselineRequirementsChecker createBaselineRequirementsChecker(CertificateVerifier certificateVerifier) {
        return new CBAdESBaselineRequirementsChecker(this, certificateVerifier);
    }

    @Override
    protected List<SignatureScope> findSignatureScopes() {
        return new CBAdESSignatureScopeFinder().findSignatureScope(this);
    }

    @Override
    public SignaturePolicyStore getSignaturePolicyStore() {
        CBAdESUHeaders unsignedProperties = getUHeaders();
        if (unsignedProperties.isExist()) {
            List<CBAdESUHeadersComponent> sigPstList = unsignedProperties.getUnsignedPropertiesWithHeaderId(COSEHeaderParameter.SIG_PST.cbor());
            if (Utils.collectionSize(sigPstList) == 1) {
                CBORValue sigPst = sigPstList.get(0).getValue();
                if (!sigPst.isMap()) {
                    LOG.warn("'sigPSt' shall be a map! The entry is skipped.");
                    return null;
                }

                SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();

                CBORValue docOrLocalUri = sigPst.getAsMapOrNull(COSEHeaderParameter.SIG_PST_DOC_OR_LOCAL_URI.cbor());
                if (docOrLocalUri != null) {
                    byte[] sigPolDoc = docOrLocalUri.getAsBytesOrNull(COSEHeaderParameter.DOC_OR_LOCAL_URI_SIG_POL_DOC.cbor());
                    CBORValue sigPolLocalURI = docOrLocalUri.get(COSEHeaderParameter.DOC_OR_LOCAL_URI_SIG_POL_LOCAL_URI.cbor());
                    if (sigPolDoc == null && sigPolLocalURI == null) {
                        LOG.warn("Unable to process 'sigPSt' unprotected header parameter: " +
                                "One of 'sigPolDoc' or 'sigPolLocalURI' member shall be present!");
                        return null;
                    }
                    if (sigPolDoc != null) {
                        signaturePolicyStore.setSignaturePolicyContent(new InMemoryDocument(sigPolDoc));
                    }
                    if (sigPolLocalURI != null) {
                        signaturePolicyStore.setSigPolDocLocalURI(CBORUtils.fromUri(sigPolLocalURI));
                    }

                } else {
                    LOG.warn("Unable to process 'sigPSt' unprotected header parameter: " +
                            "mandatory 'docOrLocalUri' member is not present or malformed!");
                    return null;
                }

                CBORValue spDSpec = sigPst.getAsMapOrNull(COSEHeaderParameter.SIG_PST_SP_D_SPEC.cbor());
                if (spDSpec != null) {
                    String oid = CBORUtils.fromUri(spDSpec.get(COSEHeaderParameter.OID_ID.cbor()));
                    oid = DSSUtils.getObjectIdentifierValue(oid);
                    if (Utils.isStringNotBlank(oid)) {
                        SpDocSpecification spDocSpecification = new SpDocSpecification();
                        spDocSpecification.setId(oid);

                        String desc = spDSpec.getAsStringOrNull(COSEHeaderParameter.OID_DESC.cbor());
                        spDocSpecification.setDescription(desc);
                        CBORValue docRefs = spDSpec.getAsArrayOrNull(COSEHeaderParameter.OID_DOC_REFS.cbor());
                        spDocSpecification.setDocumentationReferences(toListOfUriStrings(docRefs).toArray(new String[0]));
                        signaturePolicyStore.setSpDocSpecification(spDocSpecification);

                    } else {
                        LOG.warn("Id parameter in the OID is not conformant! The entry is skipped.");
                    }
                }

                return signaturePolicyStore;
            }
        }
        return null;
    }

    @Override
    public List<AdvancedSignature> getCounterSignatures() {
        if (counterSignatures != null) {
            return counterSignatures;
        }
        counterSignatures = new ArrayList<>();

        COSEUnprotectedHeader bodyUnprotectedHeader = cose.getBodyUnprotectedHeader();
        COSEUnprotectedHeader signerUnprotectedHeader = cose.getSignerUnprotectedHeader();
        for (COSESignatureType coseContext : COSESignatureType.values()) {
            CBORValue headerKey = CBORValueFactory.toCBORValue(coseContext.getCounterSignatureHeaderKey());
            if (headerKey != null) {
                CBORValue headerValue = null;
                boolean bodyStructure = false;
                if (signerUnprotectedHeader != null) {
                    headerValue = signerUnprotectedHeader.getHeader(headerKey);
                }
                if (headerValue == null && bodyUnprotectedHeader != null && !isCounterSignature()) {
                    headerValue = bodyUnprotectedHeader.getHeader(headerKey);
                    bodyStructure = true;
                }
                if (headerValue != null) { // is present
                    counterSignatures.addAll(CBAdESUtils.buildCounterSignatures(this, headerKey, headerValue, bodyStructure));
                }
            }
        }

        List<CBAdESUHeadersComponent> uHeadersAttributes = getUHeaders().getAttributes();
        if (Utils.isCollectionNotEmpty(uHeadersAttributes)) {
            for (CBAdESUHeadersComponent uHeader : uHeadersAttributes) {
                counterSignatures.addAll(CBAdESUtils.buildCounterSignatures(this, uHeader));
            }
        }
        return counterSignatures;
    }

    @Override
    protected List<String> validateStructure() {
        List<String> validationErrors = CBAdESUtils.validateAgainstCBAdESSchema(cose);
        if (Utils.isCollectionNotEmpty(validationErrors)) {
            LOG.warn("Error(s) occurred during the CDDL schema validation : {}", validationErrors);
        }
        return validationErrors;
    }

    @Override
    public String getDAIdentifier() {
        // not applicable for CB-AdES
        return null;
    }

    @Override
    public void addExternalTimestamp(TimestampToken timestamp) {
        throw new UnsupportedOperationException("The method addExternalTimestamp(timestamp) is not supported for CB-AdES!");
    }

}
