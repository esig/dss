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
package eu.europa.esig.dss.validation.process;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.SubContext;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

/**
 * Contains utils for a validation process
 */
public class ValidationProcessUtils {

	/** The Validation policy date format */
	private static final String DATE_FORMAT = "yyyy-MM-dd HH:mm";

	/** The prefix used for "urn:oid:" definition as per RFC 3061 */
	private static final String URN_OID_PREFIX = "urn:oid:";

	/**
	 * Empty constructor
	 */
	private ValidationProcessUtils() {
		// empty
	}
	
	/**
	 * Verifies if the revocation check is required for the OCSP Responder's certificate
	 *
	 * RFC 2560 : 4.2.2.2.1  Revocation Checking of an Authorized Responder
	 * 
	 * A CA may specify that an OCSP client can trust a responder for the
	 * lifetime of the responder's certificate. The CA does so by including
	 * the extension id-pkix-ocsp-nocheck.
	 *
	 * @param certificate {@link CertificateWrapper} to check
	 * @return TRUE if the revocation check is required for the OCSP Responder certificate, FALSE otherwise
	 */
	public static boolean isRevocationCheckRequired(CertificateWrapper certificate) {
		return !certificate.isTrusted() && !certificate.isSelfSigned() && !certificate.isIdPkixOcspNoCheck();
	}
	
	/**
	 * Checks if the given conclusion is allowed as a basic signature validation in order to continue
	 * the validation process with Long-Term Validation Data
	 * 
	 * @param conclusion {@link XmlConclusion} to validate
	 * @return TRUE if the result is allowed to continue the validation process, FALSE otherwise
	 */
	public static boolean isAllowedBasicSignatureValidation(XmlConclusion conclusion) {
		return Indication.PASSED.equals(conclusion.getIndication()) || (Indication.INDETERMINATE.equals(conclusion.getIndication())
				&& (SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(conclusion.getSubIndication())
						|| SubIndication.REVOKED_NO_POE.equals(conclusion.getSubIndication()) 
						|| SubIndication.REVOKED_CA_NO_POE.equals(conclusion.getSubIndication())
						|| SubIndication.TRY_LATER.equals(conclusion.getSubIndication())
						|| SubIndication.OUT_OF_BOUNDS_NO_POE.equals(conclusion.getSubIndication())
						|| SubIndication.OUT_OF_BOUNDS_NOT_REVOKED.equals(conclusion.getSubIndication())));
	}

	/**
	 * Checks if the given conclusion is allowed as a basic revocation validation in order to continue
	 * the validation process with Long-Term Validation Data
	 *
	 * @param conclusion {@link XmlConclusion} to validate
	 * @return TRUE if the result is allowed to continue the validation process, FALSE otherwise
	 */
	public static boolean isAllowedBasicRevocationDataValidation(XmlConclusion conclusion) {
		return conclusion != null && (Indication.PASSED.equals(conclusion.getIndication()) || (Indication.INDETERMINATE.equals(conclusion.getIndication())
				&& (SubIndication.REVOKED_NO_POE.equals(conclusion.getSubIndication())
				|| SubIndication.REVOKED_CA_NO_POE.equals(conclusion.getSubIndication())
				|| SubIndication.OUT_OF_BOUNDS_NO_POE.equals(conclusion.getSubIndication())
				|| SubIndication.OUT_OF_BOUNDS_NOT_REVOKED.equals(conclusion.getSubIndication())
				|| SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(conclusion.getSubIndication())
				|| SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE.equals(conclusion.getSubIndication()))));
	}

	/**
	 * Checks if the given conclusion is allowed as a basic timestamp validation in order to continue
	 * the validation process with Archival Data
	 *
	 * @param conclusion {@link XmlConclusion} to validate
	 * @return TRUE if the result is allowed to continue the validation process, FALSE otherwise
	 */
	public static boolean isAllowedBasicTimestampValidation(XmlConclusion conclusion) {
		return Indication.PASSED.equals(conclusion.getIndication()) || (Indication.INDETERMINATE.equals(conclusion.getIndication())
				&& (SubIndication.REVOKED_NO_POE.equals(conclusion.getSubIndication())
						|| SubIndication.REVOKED_CA_NO_POE.equals(conclusion.getSubIndication())
						|| SubIndication.OUT_OF_BOUNDS_NO_POE.equals(conclusion.getSubIndication())
						|| SubIndication.OUT_OF_BOUNDS_NOT_REVOKED.equals(conclusion.getSubIndication())
						|| SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(conclusion.getSubIndication())
						|| SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE.equals(conclusion.getSubIndication())));
	}

	/**
	 * Checks if the given conclusion is allowed as a validation process with a long-term validation data
	 * in order to continue the validation process with Archival Data
	 *
	 * @param conclusion {@link XmlConclusion} to validate
	 * @return TRUE if the result is allowed to continue the validation process, FALSE otherwise
	 */
	public static boolean isAllowedValidationWithLongTermData(XmlConclusion conclusion) {
		return Indication.PASSED.equals(conclusion.getIndication()) || (Indication.INDETERMINATE.equals(conclusion.getIndication())
				&& (SubIndication.REVOKED_NO_POE.equals(conclusion.getSubIndication())
					|| SubIndication.REVOKED_CA_NO_POE.equals(conclusion.getSubIndication())
					|| SubIndication.OUT_OF_BOUNDS_NO_POE.equals(conclusion.getSubIndication())
					|| SubIndication.OUT_OF_BOUNDS_NOT_REVOKED.equals(conclusion.getSubIndication())
					|| SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(conclusion.getSubIndication())
					|| SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE.equals(conclusion.getSubIndication())));
	}
	
	/**
	 * Returns a revocation data used for basic signature validation
	 * 
	 * @param token {@link TokenProxy} used in the validation process
	 * @param certificate {@link CertificateWrapper} to get a latest applicable revocation data for
	 * @param revocationData a collection of {@link CertificateRevocationWrapper} to return revocation from
	 * @param controlTime {@link Date} validation time
	 * @param bbbs a map of executed Basic Building Blocks
	 * @param poe {@link POEExtraction} a set of POEs
	 * @return {@link CertificateRevocationWrapper}
	 */
	public static CertificateRevocationWrapper getLatestAcceptableRevocationData(TokenProxy token,
					CertificateWrapper certificate, Collection<CertificateRevocationWrapper> revocationData,
					Date controlTime, Map<String, XmlBasicBuildingBlocks> bbbs, POEExtraction poe) {
		CertificateRevocationWrapper latestRevocationData = null;
		if (poe.isPOEExists(certificate.getId(), controlTime)) {
			for (CertificateRevocationWrapper revocationWrapper : revocationData) {
				XmlBasicBuildingBlocks revocationBBB = bbbs.get(revocationWrapper.getId());
				if (isAllowedBasicRevocationDataValidation(revocationBBB.getConclusion())
						&& isRevocationDataAcceptable(bbbs.get(token.getId()), certificate, revocationWrapper)
						&& revocationWrapper.getThisUpdate() != null && revocationWrapper.getThisUpdate().before(controlTime)
						&& poe.isPOEExists(revocationWrapper.getId(), controlTime)
						&& (latestRevocationData == null || (revocationWrapper.getProductionDate() != null
								&& latestRevocationData.getProductionDate().before(revocationWrapper.getProductionDate())))) {
					latestRevocationData = revocationWrapper;
				}
			}
		}
		return latestRevocationData;
	}

	/**
	 * This method verifies if there is an acceptable revocation data according to rules defined in 5.6.2.4 step 1)
	 * and returns a list of the revocation data. If none of the revocation data found,
	 * the method returns all the available revocation data
	 *
	 * @param token {@link TokenProxy} used in the validation process
	 * @param certificate {@link CertificateWrapper} to get acceptable revocation data for
	 * @param bbbs a map of {@link XmlBasicBuildingBlocks}
	 * @param poe {@link POEExtraction}
	 * @return a list of {@link CertificateRevocationWrapper}s
	 */
	public static List<CertificateRevocationWrapper> getAcceptableRevocationDataForPSVIfExistOrReturnAll(
			TokenProxy token, CertificateWrapper certificate, Map<String, XmlBasicBuildingBlocks> bbbs, POEExtraction poe) {
		List<CertificateRevocationWrapper> revocationWrappers =
				filterRevocationDataForPastSignatureValidation(token, certificate, bbbs, poe);
		if (Utils.isCollectionNotEmpty(revocationWrappers)) {
			return revocationWrappers;
		} else {
			return certificate.getCertificateRevocationData();
		}
	}

	/**
	 * This method filters revocation data for a signing certificate token according to rules defined in 5.6.2.4 step 1)
	 *
	 * @param token {@link TokenProxy} used in the validation process
	 * @param certificate {@link CertificateWrapper} to get acceptable revocation data for
	 * @param bbbs a map of {@link XmlBasicBuildingBlocks}
	 * @param poe {@link POEExtraction}
	 * @return a list of {@link CertificateRevocationWrapper}s
	 */
	private static List<CertificateRevocationWrapper> filterRevocationDataForPastSignatureValidation(
			TokenProxy token, CertificateWrapper certificate, Map<String, XmlBasicBuildingBlocks> bbbs, POEExtraction poe) {
		final List<CertificateRevocationWrapper> certificateRevocations = new ArrayList<>();

		for (CertificateRevocationWrapper certificateRevocation : certificate.getCertificateRevocationData()) {
			XmlBasicBuildingBlocks revocationBBB = bbbs.get(certificateRevocation.getId());
			CertificateWrapper revocationIssuer = certificateRevocation.getSigningCertificate();

			if (ValidationProcessUtils.isAllowedBasicRevocationDataValidation(revocationBBB.getConclusion())
					&& ValidationProcessUtils.isRevocationDataAcceptable(bbbs.get(token.getId()), certificate, certificateRevocation)
					&& revocationIssuer != null && (revocationIssuer.isTrusted() || poe.isPOEExistInRange(revocationIssuer.getId(),
					revocationIssuer.getNotBefore(), revocationIssuer.getNotAfter()))) {
				certificateRevocations.add(certificateRevocation);
			}
		}
		return certificateRevocations;
	}

	/**
	 * This method verifies if a revocation data is acceptable for the given {@code certificate} according
	 * to the validation performed within {@code bbb}
	 *
	 * @param bbb {@link XmlBasicBuildingBlocks} of the validating token
	 * @param certificate {@link CertificateWrapper} concerned certificate
	 * @param revocationData {@link RevocationWrapper} to check
	 * @return TRUE if the revocation data is acceptable, FALSE otherwise
	 */
	public static boolean isRevocationDataAcceptable(XmlBasicBuildingBlocks bbb, CertificateWrapper certificate,
													 RevocationWrapper revocationData) {
		XmlRAC xmlRAC = getRevocationAcceptanceCheckerResult(bbb, certificate.getId(), revocationData.getId());
		return xmlRAC != null && xmlRAC.getConclusion() != null && Indication.PASSED.equals(xmlRAC.getConclusion().getIndication());
	}

	/**
	 * Return a corresponding {@code XmlRAC} result for the given {@code certificate} and {@code revocationData}
	 *
	 * @param bbb {@link XmlBasicBuildingBlocks} of the validating token
	 * @param certificateId {@link String} concerned certificate id
	 * @param revocationDataId {@link String} revocation data id to check
	 * @return {@link XmlRAC}
	 */
	public static XmlRAC getRevocationAcceptanceCheckerResult(XmlBasicBuildingBlocks bbb, String certificateId,
															  String revocationDataId) {
		if (bbb != null) {
			XmlXCV xcv = bbb.getXCV();
			if (xcv != null) {
				XmlSubXCV subXCV = getXmlSubXCVForId(xcv.getSubXCV(), certificateId);
				if (subXCV != null) {
					XmlCRS crs = subXCV.getCRS();
					if (crs != null) {
						List<XmlRAC> racs = crs.getRAC();
						XmlRAC rac = getXmlRACForId(racs, revocationDataId);
						if (rac != null) {
							return rac;
						}
					}
				}
			}
		}
		return null;
	}

	private static XmlSubXCV getXmlSubXCVForId(List<XmlSubXCV> subXCVs, String tokenId) {
		for (XmlSubXCV subXCV : subXCVs) {
			if (tokenId.equals(subXCV.getId())) {
				return subXCV;
			}
		}
		return null;
	}

	private static XmlRAC getXmlRACForId(List<XmlRAC> racs, String tokenId) {
		if (Utils.isCollectionNotEmpty(racs)) {
			for (XmlRAC rac : racs) {
				if (tokenId.equals(rac.getId())) {
					return rac;
				}
			}
		}
		return null;
	}
	
	/**
	 * Returns a formatted String representation of a given Date
	 * 
	 * @param date {@link Date} to be pretty-printed
	 * @return {@link String} formatted date
	 */
	public static String getFormattedDate(Date date) {
		SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		return sdf.format(date);
	}
	
	/**
	 * Builds a String message from the provided {@code messageTag}
	 * 
	 * @param i18nProvider {@link I18nProvider} to build a message
	 * @param messageTag   {@link MessageTag} defining the message to be build
	 * @param args         the arguments to fill the message
	 * @return final message {@link String}
	 */
	public static String buildStringMessage(I18nProvider i18nProvider, MessageTag messageTag, Object... args) {
		if (messageTag != null) {
			return i18nProvider.getMessage(messageTag, args);
		}
		return null;
	}

	/**
	 * Returns the message tag for the given context (signature creation,...)
	 * 
	 * @param context the context
	 * @return the related message tag
	 */
	public static MessageTag getCryptoPosition(Context context) {
		switch (context) {
		case SIGNATURE:
		case COUNTER_SIGNATURE:
			return MessageTag.ACCM_POS_SIG_SIG;
		case TIMESTAMP:
			return MessageTag.ACCM_POS_TST_SIG;
		case REVOCATION:
			return MessageTag.ACCM_POS_REVOC_SIG;
		case CERTIFICATE:
			return MessageTag.ACCM_POS_CERT_CHAIN;
		default:
			throw new IllegalArgumentException("Unsupported context " + context);
		}
	}

	/**
	 * Returns the message tag for the certificate chain of the given context
	 * 
	 * @param context the context
	 * @return the related message tag
	 */
	public static MessageTag getCertificateChainCryptoPosition(Context context) {
		switch (context) {
		case SIGNATURE:
		case COUNTER_SIGNATURE:
			return MessageTag.ACCM_POS_CERT_CHAIN_SIG;
		case TIMESTAMP:
			return MessageTag.ACCM_POS_CERT_CHAIN_TST;
		case REVOCATION:
			return MessageTag.ACCM_POS_CERT_CHAIN_REVOC;
		case CERTIFICATE:
			return MessageTag.ACCM_POS_CERT_CHAIN;
		default:
			throw new IllegalArgumentException("Unsupported context " + context);
		}
	}
	
	/**
	 * Returns crypto position MessageTag for the given XmlDigestMatcher
	 * 
	 * @param digestMatcher {@link XmlDigestMatcher} to get crypto position for
	 * @return {@link MessageTag} position
	 */
	public static MessageTag getDigestMatcherCryptoPosition(XmlDigestMatcher digestMatcher) {
		switch (digestMatcher.getType()) {
		case OBJECT:
		case REFERENCE:
		case XPOINTER:
			return MessageTag.ACCM_POS_REF;
		case MANIFEST:
			return MessageTag.ACCM_POS_MAN;
		case MANIFEST_ENTRY:
			return MessageTag.ACCM_POS_MAN_ENT;
		case SIGNED_PROPERTIES:
			return MessageTag.ACCM_POS_SIGND_PRT;
		case KEY_INFO:
			return MessageTag.ACCM_POS_KEY;
		case SIGNATURE_PROPERTIES:
			return MessageTag.ACCM_POS_SIGNTR_PRT;
		case COUNTER_SIGNATURE:
		case COUNTER_SIGNED_SIGNATURE_VALUE:
			return MessageTag.ACCM_POS_CNTR_SIG;
		case MESSAGE_DIGEST:
			return MessageTag.ACCM_POS_MES_DIG;
		case CONTENT_DIGEST:
			return MessageTag.ACCM_POS_CON_DIG;
		case JWS_SIGNING_INPUT_DIGEST:
			return MessageTag.ACCM_POS_JWS;
		case SIG_D_ENTRY:
			return MessageTag.ACCM_POS_SIG_D_ENT;
		case MESSAGE_IMPRINT:
			return MessageTag.ACCM_POS_MESS_IMP;
		default:
			throw new IllegalArgumentException(String.format("The provided DigestMatcherType '%s' is not supported!",
					digestMatcher.getType()));
		}
	}

	/**
	 * Returns MessageTag associated with the given timestamp type
	 *
	 * @param timestampType {@link TimestampType} to get related MessageTag for
	 * @return {@link MessageTag}
	 */
	public static MessageTag getTimestampTypeMessageTag(TimestampType timestampType) {
		if (timestampType.isContentTimestamp()) {
			return MessageTag.TST_TYPE_CONTENT_TST;
		} else if (timestampType.isSignatureTimestamp()) {
			return MessageTag.TST_TYPE_SIGNATURE_TST;
		} else if (timestampType.isValidationDataTimestamp()) {
			return MessageTag.TST_TYPE_VD_TST;
		} else if (timestampType.isDocumentTimestamp()) {
			return MessageTag.TST_TYPE_DOC_TST;
		} else if (timestampType.isArchivalTimestamp()) {
			return MessageTag.TST_TYPE_ARCHIVE_TST;
		} else {
			throw new IllegalArgumentException(
					String.format("The TimestampType '%s' is not supported!", timestampType));
		}
	}

	/**
	 * Returns the message tag for the given context
	 *
	 * @param context {@link Context}
	 * @return {@link MessageTag}
	 */
	public static MessageTag getContextPosition(Context context) {
		switch (context) {
			case SIGNATURE:
			case COUNTER_SIGNATURE:
			case CERTIFICATE:
				return MessageTag.SIGNATURE;
			case TIMESTAMP:
				return MessageTag.TIMESTAMP;
			case REVOCATION:
				return MessageTag.ACCM_POS_CERT_CHAIN_REVOC;
			default:
				throw new IllegalArgumentException("Unsupported context " + context);
		}
	}

	/**
	 * Returns the message tag for the given subContext
	 *
	 * @param subContext {@link SubContext}
	 * @return {@link MessageTag}
	 */
	public static MessageTag getSubContextPosition(SubContext subContext) {
		switch (subContext) {
			case SIGNING_CERT:
				return MessageTag.SIGNING_CERTIFICATE;
			case CA_CERTIFICATE:
				return MessageTag.CA_CERTIFICATE;
			default:
				throw new IllegalArgumentException("Unsupported subContext " + subContext);
		}
	}
	/**
	 * Transforms the given OID to a URN format as per RFC 3061
	 * e.g. "1.2.3" to "urn:oid:1.2.3"
	 *
	 * @param oid {@link String}
	 * @return {@link String} urn
	 */
	public static String toUrnOid(String oid) {
		if (oid == null) {
			return null;
		}
		return URN_OID_PREFIX + oid;
	}

}
