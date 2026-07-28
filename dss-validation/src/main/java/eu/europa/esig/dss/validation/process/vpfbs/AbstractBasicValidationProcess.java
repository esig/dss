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
package eu.europa.esig.dss.validation.process.vpfbs;

import eu.europa.esig.dss.detailedreport.jaxb.XmlAOV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicValidation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlISC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVCI;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.vpfbs.checks.BasicValidationProcessCheck;
import eu.europa.esig.dss.validation.process.vpfbs.checks.ContentTimestampsCheck;
import eu.europa.esig.dss.validation.process.vpfbs.checks.CryptographicVerificationResultCheck;
import eu.europa.esig.dss.validation.process.vpfbs.checks.FormatCheckingResultCheck;
import eu.europa.esig.dss.validation.process.vpfbs.checks.IdentificationOfSigningCertificateResultCheck;
import eu.europa.esig.dss.validation.process.vpfbs.checks.SignatureAcceptanceValidationResultCheck;
import eu.europa.esig.dss.validation.process.vpfbs.checks.SigningCertificateNotRevokedCheck;
import eu.europa.esig.dss.validation.process.vpfbs.checks.TimestampGenerationTimeNotAfterCertificateExpirationCheck;
import eu.europa.esig.dss.validation.process.vpfbs.checks.TimestampGenerationTimeNotAfterCryptographicConstraintsExpirationCheck;
import eu.europa.esig.dss.validation.process.vpfbs.checks.TimestampGenerationTimeNotAfterRevocationTimeCheck;
import eu.europa.esig.dss.validation.process.vpfbs.checks.ValidationContextInitializationResultCheck;
import eu.europa.esig.dss.validation.process.vpfbs.checks.ValidationTimeAtCertificateValidityRangeCheck;
import eu.europa.esig.dss.validation.process.vpfbs.checks.X509CertificateValidationResultCheck;
import eu.europa.esig.dss.validation.process.vpftsp.checks.BasicTimestampValidationWithIdCheck;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * The abstract class implementing the "5.3 Validation process for Basic Signatures" process
 *
 * @param <T> implementation of the block's conclusion
 */
public abstract class AbstractBasicValidationProcess<T extends XmlConstraintsConclusion> extends Chain<T> {

    /** Diagnostic Data */
    protected final DiagnosticData diagnosticData;

    /** The token to be validated */
    protected final TokenProxy token;

    /** Map of BasicBuildingBlocks */
    protected final Map<String, XmlBasicBuildingBlocks> bbbs;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param diagnosticData {@link DiagnosticData}
     * @param token {@link TokenProxy}
     * @param bbbs map of BasicBuildingBlocks
     */
    protected AbstractBasicValidationProcess(I18nProvider i18nProvider, T result, DiagnosticData diagnosticData,
                                             TokenProxy token, Map<String, XmlBasicBuildingBlocks> bbbs) {
        super(i18nProvider, result);
        this.diagnosticData = diagnosticData;
        this.token = token;
        this.bbbs = bbbs;
    }

    @Override
    protected void initChain() {

        /* 5.3.4 Processing (ETSI TS 119 102-1 V1.2.1) */
        final XmlBasicBuildingBlocks tokenBBBs = bbbs.get(token.getId());
        if (tokenBBBs == null) {
            throw new IllegalStateException(
                    String.format("Missing Basic Building Blocks result for token with Id '%s'", token.getId()));
        }

        ChainItem<T> item = firstItem;

        /*
         * 1) The Basic Signature validation process shall perform the format checking
         * as per clause 5.2.2. If the process returns PASSED, the Basic Signature
         * validation process shall continue with the next step. Otherwise, the Basic
         * Signature validation process shall return the indication FAILED with the
         * sub-indication FORMAT_FAILURE.
         */
        XmlFC xmlFC = tokenBBBs.getFC();
        if (xmlFC != null) {
            item = firstItem = formatChecking(xmlFC);
        }

        /*
         * 2) The Basic Signature validation process shall perform the identification
         * of the signing certificate (as per clause 5.2.3) with the signature and
         * the signing certificate, if provided as a parameter. If the identification of
         * the signing certificate process returns the indication INDETERMINATE with
         * the sub-indication NO_SIGNING_CERTIFICATE_FOUND, the Basic Signature validation
         * process shall return the indication INDETERMINATE with the sub-indication
         * NO_SIGNING_CERTIFICATE_FOUND, otherwise it shall go to the next step.
         */
        XmlISC xmlISC = tokenBBBs.getISC();
        // required for all tokens
        if (firstItem == null) {
            item = firstItem = identificationOfSigningCertificate(xmlISC);
        } else {
            item = item.setNextItem(identificationOfSigningCertificate(xmlISC));
        }

        /*
         * 3) The Basic Signature validation process shall perform the Validation Context Initialization
         * as per clause 5.2.4. If the process returns INDETERMINATE with some sub-indication,
         * the Basic Signature validation process shall return the indication INDETERMINATE
         * together with that sub-indication, otherwise it shall go to the next step.
         */
        XmlVCI xmlVCI = tokenBBBs.getVCI();
        if (xmlVCI != null) {
            item = item.setNextItem(validationContextInitialization(xmlVCI));
        }

        /*
         * 4) The Basic Signature validation process shall perform the X.509 Certificate Validation
         * as per clause 5.2.6 with the following inputs:
         *    a) The signing certificate obtained in step 2). And
         *    b) X.509 validation constraints, certificate validation-data and
         *       cryptographic constraints obtained in step 3) or provided as input.
         */
        final List<TimestampWrapper> contentTimestamps = getContentTimestamps();

        XmlConclusion x509ValidationStatus = new XmlConclusion();
        XmlXCV xmlXCV = tokenBBBs.getXCV();
        if (xmlXCV != null) {

            item = item.setNextItem(x509CertificateValidation(xmlXCV));

            /*
             * If the X.509 Certificate Validation process returns the indication PASSED,
             * the Basic Signature validation process shall set X509_validation-status to PASSED
             * and it shall go to step 5).
             */
            if (isValid(xmlXCV)) {
                x509ValidationStatus.setIndication(Indication.PASSED);

            } else {
                x509ValidationStatus.setIndication(xmlXCV.getConclusion().getIndication());
                x509ValidationStatus.setSubIndication(xmlXCV.getConclusion().getSubIndication());
                /*
                 * If the X.509 Certificate Validation process returns the indication
                 * INDETERMINATE with the sub-indication REVOKED_NO_POE and if
                 * the signature contains a content-time-stamp attribute, the Basic Signature
                 * validation process shall perform the validation process for AdES time-stamps
                 * as defined in clause 5.4. If this process returns the indication PASSED and
                 * the generation time of the time-stamp token is after the revocation time,
                 * the Basic Signature validation process shall set X509_validation-status to FAILED
                 * with the sub-indication REVOKED. In all other cases, the Basic Signature validation
                 * process shall set X509_validation-status to INDETERMINATE with the sub-indication
                 * REVOKED_NO_POE. The process shall continue with step 5)
                 */
                item = item.setNextItem(signingCertificateNotRevoked(xmlXCV));

                if (Indication.INDETERMINATE.equals(xmlXCV.getConclusion().getIndication()) &&
                        SubIndication.REVOKED_NO_POE.equals(xmlXCV.getConclusion().getSubIndication()) &&
                        Utils.isCollectionNotEmpty(contentTimestamps)) {
                    Date revocationTime = getRevocationTimeForSigningCertificate();

                    item = item.setNextItem(contentTimestampsPresent(contentTimestamps));

                    for (TimestampWrapper timestampWrapper : contentTimestamps) {

                        final XmlValidationProcessBasicTimestamp timestampValidation = getTimestampValidation(timestampWrapper.getId());
                        if (timestampValidation != null) {

                            item = item.setNextItem(timestampBasicValidation(timestampWrapper, timestampValidation));

                            if (isValid(timestampValidation)) {

                                item = item.setNextItem(timestampNotAfterRevocationTime(timestampWrapper, revocationTime));

                                if (timestampWrapper.getProductionTime().after(revocationTime)) {
                                    x509ValidationStatus.setIndication(Indication.FAILED);
                                    x509ValidationStatus.setSubIndication(SubIndication.REVOKED);
                                    break;
                                }
                            }
                        }

                    }

                }

                /*
                 * If the X.509 Certificate Validation process returns the indication INDETERMINATE
                 * with the sub-indication OUT_OF_BOUNDS_NO_POE or OUT_OF_BOUNDS_NOT_REVOKED, and if
                 * the signature contains a content-time-stamp attribute, the Basic Signature
                 * validation process shall perform the validation process for AdES time-stamps as defined
                 * in clause 5.4. If it returns the indication PASSED and the generation time of
                 * the time-stamp token is after the expiration date of the signing certificate,
                 * the Basic Signature validation process shall set X509_validation-status to FAILED with
                 * the sub-indication EXPIRED. Otherwise, the Basic Signature validation process shall set
                 * X509_validation-status to INDETERMINATE with the sub-indication OUT_OF_BOUNDS_NO_POE or
                 * OUT_OF_BOUNDS_NOT_REVOKED, respectively. The process shall continue with step 5).
                 */
                item = item.setNextItem(validationTimeAtValidityRange(xmlXCV));

                if (Indication.INDETERMINATE.equals(xmlXCV.getConclusion().getIndication()) &&
                        (SubIndication.OUT_OF_BOUNDS_NO_POE.equals(xmlXCV.getConclusion().getSubIndication()) ||
                                SubIndication.OUT_OF_BOUNDS_NOT_REVOKED.equals(xmlXCV.getConclusion().getSubIndication())) &&
                        Utils.isCollectionNotEmpty(contentTimestamps)) {
                    Date certificateNotAfter = token.getSigningCertificate().getNotAfter();

                    item = item.setNextItem(contentTimestampsPresent(contentTimestamps));

                    for (TimestampWrapper timestampWrapper : contentTimestamps) {

                        final XmlValidationProcessBasicTimestamp timestampValidation = getTimestampValidation(timestampWrapper.getId());
                        if (timestampValidation != null) {

                            item = item.setNextItem(timestampBasicValidation(timestampWrapper, timestampValidation));

                            if (isValid(timestampValidation)) {

                                item = item.setNextItem(timestampNotAfterSigningCertificateNotAfterTime(timestampWrapper, certificateNotAfter));

                                if (timestampWrapper.getProductionTime().after(certificateNotAfter)) {
                                    x509ValidationStatus.setIndication(Indication.FAILED);
                                    x509ValidationStatus.setSubIndication(SubIndication.EXPIRED);
                                    break;
                                }
                            }
                        }

                    }
                }

                /*
                 * If the X.509 Certificate Validation process returns the indication INDETERMINATE
                 * with the sub-indication NO_CERTIFICATE_CHAIN_FOUND and if the signature algorithm
                 * requires the full certificate chain for determining the public key, the Basic Signature
                 * validation process shall return the indication INDETERMINATE with the sub-indication
                 * NO_CERTIFICATE_CHAIN_FOUND.
                 *
                 * In all other cases, the Basic Signature validation process shall set X509_validation-status
                 * to the indication and sub-indication returned by the X.509 Certificate Validation process
                 * and continue with step 5).
                 */

            }
        }

        /*
         * 5) The Basic Signature validation process shall perform the Cryptographic Verification
         * process as per clause 5.2.7 with the following inputs:
         *    a) The signed data object.
         *    b) The signing certificate obtained in step 2).
         *    c) The certificate chain returned in the previous step, if it was returned in step 4). And
         *    d) The SD or SDR, if given in the input.
         */
        XmlCV xmlCV = tokenBBBs.getCV();
        if (xmlCV != null) {

            item = item.setNextItem(cryptographicVerification(xmlCV));

            /*
             * If the Cryptographic Verification process returns PASSED:
             */
            if (isValid(xmlCV)) {
                /*
                 * a) If the X509_validation-status set in the previous step contains the indication PASSED,
                 * the Basic Signature validation process shall go to the next step;
                 */
                // continue

                /*
                 * b) If the X509_validation-status set in the previous step contains the indication
                 * INDETERMINATE or FAILED with any subindication, the Basic Signature validation process
                 * shall return the indication and subindication contained in X509_validation-status,
                 * with any associated information about the reason.
                 */
                if (Indication.INDETERMINATE.equals(x509ValidationStatus.getIndication()) ||
                        Indication.FAILED.equals(x509ValidationStatus.getIndication())) {

                    item = item.setNextItem(basicValidationProcess(x509ValidationStatus));

                }

                /*
                 * Otherwise, the Basic Signature validation process shall return the returned indication,
                 * sub-indication and associated information provided by the Cryptographic Verification process.
                 */
                // returned before
            }

        }

        /*
         * 6) The Basic Signature validation process shall perform the Signature Acceptance Validation
         * process as per clause 5.2.8 with the following inputs:
         *    a) the Signed Data Object(s);
         *    b) the certificate chain obtained in step 4);
         *    c) the Cryptographic Constraints; and
         *    d) the Signature Elements Constraints.
         */
        XmlSAV xmlSAV = tokenBBBs.getSAV();
        if (xmlSAV != null) {

            item = item.setNextItem(signatureAcceptanceValidation(xmlSAV));

            XmlAOV xmlAOV = tokenBBBs.getAOV();
            /*
             * If the signature acceptance validation process returns PASSED, the Basic Signature validation
             * process shall go to the next step.
             */
            if (Indication.PASSED.equals(xmlSAV.getConclusion().getIndication())) {
                // continue
            }

            /*
             * If the signature acceptance validation process returns the indication INDETERMINATE
             * with the sub-indication CRYPTO_CONSTRAINTS_FAILURE_NO_POE and the material concerned by
             * this failure is the signature value and if the signature contains a content-time-stamp attribute,
             * the Basic Signature validation process shall perform the validation process for AdES time-stamps
             * as defined in clause 5.4. If it returns the indication PASSED and the algorithm(s) concerned
             * were no longer considered reliable at the generation time of the time-stamp token,
             * the Basic Signature validation process shall return the indication INDETERMINATE with
             * the sub-indication CRYPTO_CONSTRAINTS_FAILURE. In all other cases, the Basic Signature
             * validation process shall return the indication INDETERMINATE with the sub-indication
             * CRYPTO_CONSTRAINTS_FAILURE_NO_POE.
             */
            else if (Indication.INDETERMINATE.equals(xmlSAV.getConclusion().getIndication()) &&
                    SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(xmlSAV.getConclusion().getSubIndication()) &&
                    isSignatureValueConcernedByFailure(xmlAOV) && Utils.isCollectionNotEmpty(contentTimestamps)) {

                item = item.setNextItem(contentTimestampsPresent(contentTimestamps));

                for (TimestampWrapper timestampWrapper : contentTimestamps) {

                    final XmlValidationProcessBasicTimestamp timestampValidation = getTimestampValidation(timestampWrapper.getId());
                    if (timestampValidation != null) {

                        item = item.setNextItem(timestampBasicValidation(timestampWrapper, timestampValidation));

                        if (isValid(timestampValidation)) {

                            item = item.setNextItem(timestampNotAfterCryptographicAlgorithmsExpiration(
                                    timestampWrapper, xmlAOV.getSignatureCryptographicValidation()));

                        }
                    }

                }
            }

            if (!isValid(xmlSAV)) {
                item = item.setNextItem(basicValidationProcess(xmlSAV.getConclusion()));
            }

        }

        /*
         * 7) The Basic Signature validation process shall return the success indication PASSED
         * together with the certificate chain obtained in step 4). In addition, the Basic Signature
         * validation process should return additional information extracted from the signature and/or
         * used by the intermediate steps. In particular, the SVA should provide to the DA all information
         * related to signed and unsigned attributes, including those which were not processed during
         * the validation process.
         */

    }

    /**
     * Executes "5.2.2 Format Checking" building block for the given token
     *
     * @param xmlFC {@link XmlFC}
     * @return {@link ChainItem}
     */
    protected ChainItem<T> formatChecking(final XmlFC xmlFC) {
        return new FormatCheckingResultCheck<>(i18nProvider, result, xmlFC, token, getFailLevelRule());
    }

    /**
     * Executes "5.2.3 Identification of the signing certificate" building block for the given token
     *
     * @param xmlISC {@link XmlISC}
     * @return {@link ChainItem}
     */
    protected ChainItem<T> identificationOfSigningCertificate(final XmlISC xmlISC) {
        return new IdentificationOfSigningCertificateResultCheck<>(i18nProvider, result, xmlISC, token, getFailLevelRule());
    }

    /**
     * Executes "5.2.4 Validation context initialization" building block for the given token
     *
     * @param xmlVCI {@link XmlVCI}
     * @return {@link ChainItem}
     */
    protected ChainItem<T> validationContextInitialization(final XmlVCI xmlVCI) {
        return new ValidationContextInitializationResultCheck<>(i18nProvider, result, xmlVCI, token, getFailLevelRule());
    }

    /**
     * Executes "5.2.6 X.509 certificate validation" building block for the given token
     *
     * @param xmlXCV {@link XmlXCV}
     * @return {@link ChainItem}
     */
    protected ChainItem<T> x509CertificateValidation(final XmlXCV xmlXCV) {
        return new X509CertificateValidationResultCheck<>(i18nProvider, result, xmlXCV, token, getWarnLevelRule());
    }

    private ChainItem<T> signingCertificateNotRevoked(final XmlXCV xmlXCV) {
        return new SigningCertificateNotRevokedCheck<>(i18nProvider, result, xmlXCV, token, getWarnLevelRule());
    }

    private ChainItem<T> validationTimeAtValidityRange(final XmlXCV xmlXCV) {
        return new ValidationTimeAtCertificateValidityRangeCheck<>(i18nProvider, result, xmlXCV, token, getWarnLevelRule());
    }

    private ChainItem<T> contentTimestampsPresent(final List<TimestampWrapper> contentTimestamps) {
        return new ContentTimestampsCheck<>(i18nProvider, result, contentTimestamps, getWarnLevelRule());
    }

    private ChainItem<T> timestampBasicValidation(final TimestampWrapper timestamp,
                                                  final XmlValidationProcessBasicTimestamp timestampValidation) {
        return new BasicTimestampValidationWithIdCheck<>(i18nProvider, result, timestamp, timestampValidation,
                getWarnLevelRule());
    }

    private ChainItem<T> timestampNotAfterRevocationTime(final TimestampWrapper timestamp, final Date revocationTime) {
        return new TimestampGenerationTimeNotAfterRevocationTimeCheck<>(i18nProvider, result, timestamp,
                revocationTime, getWarnLevelRule());
    }

    private ChainItem<T> timestampNotAfterSigningCertificateNotAfterTime(final TimestampWrapper timestamp,
                                                                         final Date revocationTime) {
        return new TimestampGenerationTimeNotAfterCertificateExpirationCheck<>(i18nProvider, result, timestamp,
                revocationTime, getWarnLevelRule());
    }

    /**
     * Executes "5.2.7 Cryptographic verification" building block for the given token
     *
     * @param xmlCV {@link XmlCV}
     * @return {@link ChainItem}
     */
    protected ChainItem<T> cryptographicVerification(final XmlCV xmlCV) {
        return new CryptographicVerificationResultCheck<>(i18nProvider, result, xmlCV, token, getFailLevelRule());
    }

    /**
     * Executes "5.2.8 Signature Acceptance Validation (SAV)" building block for the given token
     *
     * @param xmlSAV {@link XmlSAV}
     * @return {@link ChainItem}
     */
    protected ChainItem<T> signatureAcceptanceValidation(final XmlSAV xmlSAV) {
        return new SignatureAcceptanceValidationResultCheck<>(i18nProvider, result, xmlSAV, token, getWarnLevelRule());
    }

    private ChainItem<T> timestampNotAfterCryptographicAlgorithmsExpiration(
            final TimestampWrapper timestamp, final XmlCryptographicValidation cryptographicValidation) {
        return new TimestampGenerationTimeNotAfterCryptographicConstraintsExpirationCheck<>(i18nProvider, result,
                timestamp, cryptographicValidation, getFailLevelRule());
    }

    /**
     * Executes a final validation check of the "5.3 Validation process for Basic Signatures" block
     *
     * @param xmlConclusion {@link XmlConclusion} containing the result of the validation process for Basic Signatures
     * @return {@link ChainItem}
     */
    protected ChainItem<T> basicValidationProcess(final XmlConclusion xmlConclusion) {
        return new BasicValidationProcessCheck<>(i18nProvider, result, xmlConclusion, token, getFailLevelRule());
    }

    /**
     * Returns a list of content timestamps
     *
     * @return a list of {@link TimestampWrapper}s
     */
    protected List<TimestampWrapper> getContentTimestamps() {
        return Collections.emptyList();
    }

    /**
     * Gets the corresponding validation result for a timestamp with the given Id
     *
     * @param timestampId {@link String} Id of a timestamp to get validation result for
     * @return {@link XmlValidationProcessBasicTimestamp}
     */
    protected XmlValidationProcessBasicTimestamp getTimestampValidation(String timestampId) {
        return null;
    }

    private Date getRevocationTimeForSigningCertificate() {
        CertificateWrapper signingCertificate = token.getSigningCertificate();
        if (signingCertificate != null && Utils.isCollectionNotEmpty(signingCertificate.getCertificateRevocationData())) {
            return diagnosticData.getLatestRevocationDataForCertificate(signingCertificate).getRevocationDate();
        }
        return null;
    }

    private boolean isSignatureValueConcernedByFailure(XmlAOV xmlAOV) {
        XmlCryptographicValidation cryptographicValidation = xmlAOV.getSignatureCryptographicValidation();
        return cryptographicValidation != null && !isValidConclusion(cryptographicValidation.getConclusion());
    }

    @Override
    protected void collectMessages(XmlConclusion conclusion, XmlConstraint constraint) {
        if (XmlBlockType.CNT_TST_BBB.equals(constraint.getBlockType())) {
            XmlMessage error = constraint.getError();
            if (error != null) {
                conclusion.getErrors().add(error);
            }
            super.collectMessages(conclusion, constraint);
        }
    }

    @Override
    protected void collectAdditionalMessages(XmlConclusion conclusion) {
        final XmlBasicBuildingBlocks tokenBBBs = bbbs.get(token.getId());
        if (tokenBBBs != null) {
            conclusion.getErrors().clear();
            conclusion.getErrors().addAll(tokenBBBs.getConclusion().getErrors());
            conclusion.getWarnings().clear();
            conclusion.getWarnings().addAll(tokenBBBs.getConclusion().getWarnings());
            conclusion.getInfos().clear();
            conclusion.getInfos().addAll(tokenBBBs.getConclusion().getInfos());

            for (XmlConstraint constraint : result.getConstraint()) {
                collectMessages(conclusion, constraint);
            }
        }
    }

}
