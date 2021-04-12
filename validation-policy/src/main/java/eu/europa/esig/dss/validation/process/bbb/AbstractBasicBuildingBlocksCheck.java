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
package eu.europa.esig.dss.validation.process.bbb;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicValidation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlISC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVCI;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Abstract BasicBuildingBlock check
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public abstract class AbstractBasicBuildingBlocksCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	/** Diagnostic data */
	private final DiagnosticData diagnosticData;

	/** Contains BasicBuildingBlocks performed for the token */
	private final XmlBasicBuildingBlocks tokenBBBs;

	/** Map of token ids and related BBBs */
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	/** The validation indication */
	private Indication indication;

	/** The validation subIndication */
	private SubIndication subIndication;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param diagnosticData {@link DiagnosticData}
	 * @param tokenBBBs {@link XmlBasicBuildingBlocks} for the current token
	 * @param bbbs map of all BBBs
	 * @param constraint {@link LevelConstraint}
	 */
	public AbstractBasicBuildingBlocksCheck(I18nProvider i18nProvider, T result, DiagnosticData diagnosticData,
											XmlBasicBuildingBlocks tokenBBBs, Map<String, XmlBasicBuildingBlocks> bbbs,
											LevelConstraint constraint) {
		super(i18nProvider, result, constraint, tokenBBBs.getId());
		this.diagnosticData = diagnosticData;
		this.tokenBBBs = tokenBBBs;
		this.bbbs = bbbs;
	}

	@Override
	protected boolean process() {

		/* 5.3.4 Processing (ETSI TS 119 102-1 V1.2.1) */

		/*
		 * 1) The Basic Signature validation process shall perform the format checking
		 * as per clause 5.2.2. If the process returns PASSED, the Basic Signature
		 * validation process shall continue with the next step. Otherwise, the Basic
		 * Signature validation process shall return the indication FAILED with the
		 * sub-indication FORMAT_FAILURE.
		 */
		XmlFC fc = tokenBBBs.getFC();
		if (fc != null) {
			XmlConclusion fcConclusion = fc.getConclusion();
			if (!Indication.PASSED.equals(fcConclusion.getIndication())) {
				indication = Indication.FAILED;
				subIndication = SubIndication.FORMAT_FAILURE;
				return false;
			}
		}

		/*
		 * 2) The Basic Signature validation process shall perform the identification of
		 * the signing certificate (as per clause 5.2.3) with the signature and the
		 * signing certificate, if provided as a parameter. If the identification of the
		 * signing certificate process returns the indication INDETERMINATE with the
		 * sub-indication NO_SIGNING_CERTIFICATE_FOUND, the Basic Signature validation
		 * process shall return the indication INDETERMINATE with the sub-indication
		 * NO_SIGNING_CERTIFICATE_FOUND, otherwise it shall go to the next step.
		 */
		XmlISC isc = tokenBBBs.getISC();
		XmlConclusion iscConclusion = isc.getConclusion();
		if (Indication.INDETERMINATE.equals(iscConclusion.getIndication())
				&& SubIndication.NO_SIGNING_CERTIFICATE_FOUND.equals(iscConclusion.getSubIndication())) {
			indication = iscConclusion.getIndication();
			subIndication = iscConclusion.getSubIndication();
			return false;
		}

		/*
		 * 3) The Basic Signature validation process shall perform the Validation
		 * Context Initialization as per clause 5.2.4. If the process returns
		 * INDETERMINATE with some sub-indication, the Basic Signature validation
		 * process shall return the indication INDETERMINATE together with that
		 * sub-indication, otherwise it shall go to the next step.
		 */
		XmlVCI vci = tokenBBBs.getVCI();
		if (vci != null) {
			XmlConclusion vciConclusion = vci.getConclusion();
			if (Indication.INDETERMINATE.equals(vciConclusion.getIndication())) {
				indication = vciConclusion.getIndication();
				subIndication = vciConclusion.getSubIndication();
				return false;
			}
		}

		/*
		 * 4) The Basic Signature validation process shall perform the X.509 Certificate
		 * Validation as per clause 5.2.6 with the following inputs:
		 * 
		 * a) The signing certificate obtained in step 2). And
		 * 
		 * b) X.509 validation constraints, certificate validation-data and
		 * cryptographic constraints obtained in step 3) or provided as input.
		 * 
		 * If the X.509 Certificate Validation process returns the indication PASSED,
		 * the Basic Signature validation process shall set X509_validation-status to
		 * PASSED and it shall go to step 5).
		 * 
		 * NOTE 2: X509_validation-status is an internal variable. This is done because
		 * the cryptographic validation has not been performed yet. Other building
		 * blocks assume that when this building block returns an INDETERMINATE status
		 * with a sub-indication related to X.509 certificate validation, cryptographic
		 * validation has been performed successfully. Cryptographic validation can, in
		 * some cases, only be performed after X.509 validation.
		 * 
		 * If the X.509 Certificate Validation process returns the indication
		 * INDETERMINATE with the sub-indication REVOKED_NO_POE and if the signature
		 * contains a content-time-stamp attribute, the Basic Signature validation
		 * process shall perform the validation process for AdES time-stamps as defined
		 * in clause 5.4. If this process returns the indication PASSED and the
		 * generation time of the time-stamp token is after the revocation time, the
		 * Basic Signature validation process shall set X509_validation-status to FAILED
		 * with the sub-indication REVOKED. In all other cases, the Basic Signature
		 * validation process shall set X509_validation-status to INDETERMINATE with the
		 * sub-indication REVOKED_NO_POE. The process shall continue with step 5).
		 */
		XmlXCV xcv = tokenBBBs.getXCV();
		XmlConclusion x509ValidationStatus = null;
		if (xcv != null) {

			XmlConclusion xcvConclusion = x509ValidationStatus = xcv.getConclusion();

			x509ValidationStatus.setIndication(xcvConclusion.getIndication());
			x509ValidationStatus.setSubIndication(xcvConclusion.getSubIndication());

			if (Indication.INDETERMINATE.equals(xcvConclusion.getIndication()) && SubIndication.REVOKED_NO_POE.equals(xcvConclusion.getSubIndication())) {
				SignatureWrapper currentSignature = diagnosticData.getSignatureById(tokenBBBs.getId());
				if (currentSignature != null && isThereValidContentTimestampAfterDate(currentSignature, getRevocationDateForSigningCertificate(currentSignature))) {
					x509ValidationStatus.setIndication(Indication.FAILED);
					x509ValidationStatus.setSubIndication(SubIndication.REVOKED);
				}
			}
			/*
			 * If the X.509 Certificate Validation process returns the indication
			 * INDETERMINATE with the sub-indication OUT_OF_BOUNDS_NO_POE or
			 * OUT_OF_BOUNDS_NOT_REVOKED, and if the signature contains a content-time-stamp
			 * attribute, the Basic Signature validation process shall perform the
			 * validation process for AdES time-stamps as defined in clause 5.4. If it
			 * returns the indication PASSED and the generation time of the time-stamp token
			 * is after the expiration date of the signing certificate, the Basic Signature
			 * validation process shall set X509_validation-status to FAILED with the
			 * sub-indication EXPIRED. Otherwise, the Basic Signature validation process
			 * shall set X509_validation-status to INDETERMINATE with the sub-indication
			 * OUT_OF_BOUNDS_NO_POE or OUT_OF_BOUNDS_NOT_REVOKED, respectively. The process
			 * shall continue with step 5).
			 */
			else if (Indication.INDETERMINATE.equals(xcvConclusion.getIndication())
					&& (SubIndication.OUT_OF_BOUNDS_NO_POE.equals(xcvConclusion.getSubIndication())
							|| SubIndication.OUT_OF_BOUNDS_NOT_REVOKED.equals(xcvConclusion.getSubIndication()))) {

				SignatureWrapper currentSignature = diagnosticData.getSignatureById(tokenBBBs.getId());
				if (currentSignature != null && isThereValidContentTimestampAfterDate(currentSignature, getExpirationDateForSigningCertificate(currentSignature))) {
					x509ValidationStatus.setIndication(Indication.FAILED);
					x509ValidationStatus.setSubIndication(SubIndication.EXPIRED);
				}
			}
			/*
			 * If the X.509 Certificate Validation process returns the indication
			 * INDETERMINATE with the sub-indication NO_CERTIFICATE_CHAIN_FOUND and if the
			 * signature algorithm requires the full certificate chain for determining the
			 * public key, the Basic Signature validation process shall return the
			 * indication INDETERMINATE with the sub-indication NO_CERTIFICATE_CHAIN_FOUND.
			 * 
			 * In all other cases, the Basic Signature validation process shall set
			 * X509_validation-status to the indication and sub-indication returned by the
			 * X.509 Certificate Validation process and continue with step 5).
			 */

			// x509ValidationStatus is filled at the beginning
		}

		/*
		 * 5) The Basic Signature validation process shall perform the Cryptographic
		 * Verification process as per clause 5.2.7 with the following inputs:
		 * 
		 * a) The signed data object.
		 * 
		 * b) The signing certificate obtained in step 2).
		 * 
		 * c) The certificate chain returned in the previous step, if it was returned in
		 * step 4). And
		 * 
		 * d) The SD or SDR, if given in the input.
		 * 
		 * If the Cryptographic Verification process returns PASSED:
		 * 
		 * a) If the X509_validation-status set in the previous step contains the
		 * indication PASSED, the Basic Signature validation process shall go to the
		 * next step;
		 * 
		 * b) If the X509_validation-status set in the previous step contains the
		 * indication INDETERMINATE or FAILED with any subindication, the Basic
		 * Signature validation process shall return the indication and subindication
		 * contained in X509_validation-status, with any associated information about
		 * the reason.
		 * 
		 * Otherwise, the Basic Signature validation process shall return the returned
		 * indication, sub-indication and associated information provided by the
		 * Cryptographic Verification process.
		 */
		XmlCV cv = tokenBBBs.getCV();
		XmlConclusion cvConclusion = cv.getConclusion();
		if (Indication.PASSED.equals(cvConclusion.getIndication())) {
			if (x509ValidationStatus != null && !Indication.PASSED.equals(x509ValidationStatus.getIndication())) {
				indication = x509ValidationStatus.getIndication();
				subIndication = x509ValidationStatus.getSubIndication();
				return false;
			}
		} else {
			indication = cvConclusion.getIndication();
			subIndication = cvConclusion.getSubIndication();
			return false;
		}

		/*
		 * 6) The Basic Signature validation process shall perform the Signature
		 * Acceptance Validation process as per clause 5.2.8 with the following inputs:
		 * 
		 * a) the Signed Data Object(s);
		 * 
		 * b) the certificate chain obtained in step 4);
		 * 
		 * c) the Cryptographic Constraints; and
		 * 
		 * d) the Signature Elements Constraints.
		 * 
		 * If the signature acceptance validation process returns PASSED, the Basic
		 * Signature validation process shall go to the next step.
		 * 
		 * If the signature acceptance validation process returns the indication
		 * INDETERMINATE with the sub-indication CRYPTO_CONSTRAINTS_FAILURE_NO_POE and
		 * the material concerned by this failure is the signature value and if the
		 * signature contains a content-time-stamp attribute, the Basic Signature
		 * validation process shall perform the validation process for AdES time-stamps
		 * as defined in clause 5.4. If it returns the indication PASSED and the
		 * algorithm(s) concerned were no longer considered reliable at the generation
		 * time of the time-stamp token, the Basic Signature validation process shall
		 * return the indication INDETERMINATE with the sub-indication
		 * CRYPTO_CONSTRAINTS_FAILURE. In all other cases, the Basic Signature
		 * validation process shall return the indication INDETERMINATE with the
		 * sub-indication CRYPTO_CONSTRAINTS_FAILURE_NO_POE.
		 * 
		 * NOTE 3: The content time-stamp is a signed attribute and hence proves that
		 * the signature value was produced after the generation time of the time-stamp
		 * token.
		 * 
		 * NOTE 4: In case this clause returns
		 * INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE, the validation process for
		 * Signatures providing Long Term Availability and Integrity of Validation
		 * Material can be used to validate the signature, if other POE (e.g. from a
		 * trusted archive) exist.
		 * 
		 * In all other cases, the Basic Signature validation process shall return the
		 * indication and associated information returned by the signature acceptance
		 * validation building block
		 */
		XmlSAV sav = tokenBBBs.getSAV();
		XmlConclusion savConclusion = sav.getConclusion();
		if (Indication.INDETERMINATE.equals(savConclusion.getIndication())
				&& SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(savConclusion.getSubIndication())) {

			XmlCryptographicValidation cryptographicValidation = sav.getCryptographicValidation();

			SignatureWrapper currentSignature = diagnosticData.getSignatureById(tokenBBBs.getId());
			if (currentSignature != null && cryptographicValidation != null
					&& isSignatureValueConcernedByFailure(currentSignature, cryptographicValidation)
					&& isThereValidContentTimestampAfterDate(currentSignature, cryptographicValidation.getNotAfter())) {
				indication = Indication.INDETERMINATE;
				subIndication = SubIndication.CRYPTO_CONSTRAINTS_FAILURE;
				return false;
			}

			indication = Indication.INDETERMINATE;
			subIndication = SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE;
			return false;

		} else if (!Indication.PASSED.equals(savConclusion.getIndication())) {
			indication = savConclusion.getIndication();
			subIndication = savConclusion.getSubIndication();
			return false;
		}

		return true;
	}
	
	private boolean isSignatureValueConcernedByFailure(SignatureWrapper currentSignature,
													   XmlCryptographicValidation cryptographicValidation) {
		return currentSignature.getId().equals(cryptographicValidation.getConcernedMaterial());
	}

	private boolean isThereValidContentTimestampAfterDate(SignatureWrapper currentSignature, Date date) {
		List<TimestampWrapper> contentTimestamps = currentSignature.getContentTimestamps();
		if (Utils.isCollectionNotEmpty(contentTimestamps) && date != null) {
			for (TimestampWrapper timestamp : contentTimestamps) {
				if (isValidTimestamp(timestamp)) {
					Date tspProductionTime = timestamp.getProductionTime();
					if (tspProductionTime.after(date)) {
						return true;
					}
				}
			}
		}
		return false;
	}

	private boolean isValidTimestamp(TimestampWrapper timestamp) {
		XmlBasicBuildingBlocks timestampBasicBuildingBlocks = bbbs.get(timestamp.getId());
		return (timestampBasicBuildingBlocks != null && timestampBasicBuildingBlocks.getConclusion() != null)
				&& Indication.PASSED.equals(timestampBasicBuildingBlocks.getConclusion().getIndication());
	}

	private Date getRevocationDateForSigningCertificate(SignatureWrapper currentSignature) {
		CertificateWrapper signingCertificate = currentSignature.getSigningCertificate();
		if (signingCertificate != null && Utils.isCollectionNotEmpty(signingCertificate.getCertificateRevocationData())) {
			return diagnosticData.getLatestRevocationDataForCertificate(signingCertificate).getRevocationDate();
		}
		return null;
	}

	private Date getExpirationDateForSigningCertificate(SignatureWrapper currentSignature) {
		CertificateWrapper signingCertificate = currentSignature.getSigningCertificate();
		if (signingCertificate != null) {
			return signingCertificate.getNotAfter();
		}
		return null;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return indication;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return subIndication;
	}

	@Override
	protected List<XmlMessage> getPreviousErrors() {
		return tokenBBBs.getConclusion().getErrors();
	}

}
