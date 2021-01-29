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
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

/**
 * Contains utils for a validation process
 */
public class ValidationProcessUtils {

	/** The Validation policy date format */
	private static final String DATE_FORMAT = "yyyy-MM-dd HH:mm";
	
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
	 * @param controlTime {@link Date} validation time
	 * @return TRUE if the revocation check is required for the OCSP Responder certificate, FALSE otherwise
	 */
	public static boolean isRevocationCheckRequired(CertificateWrapper certificate, Date controlTime) {
		if (certificate.isIdPkixOcspNoCheck()) {
			return !(controlTime.compareTo(certificate.getNotBefore()) >= 0 && controlTime.compareTo(certificate.getNotAfter()) <= 0);
		}
		return true;
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
	 * Returns a revocation data used for basic signature validation
	 * 
	 * @param certificate {@link CertificateWrapper} to get a latest applicable revocation data for
	 * @param bbb {@link XmlBasicBuildingBlocks} validation of a token
	 * @return {@link CertificateRevocationWrapper}
	 */
	public static CertificateRevocationWrapper getLatestAcceptableRevocationData(CertificateWrapper certificate, XmlBasicBuildingBlocks bbb) {
		if (bbb != null && bbb.getXCV() != null) {
			for (XmlSubXCV subXCV : bbb.getXCV().getSubXCV()) {
				// rfc.getId can be null if no revocation data is available
				if (certificate.getId().equals(subXCV.getId()) && (subXCV.getRFC() != null) && (subXCV.getRFC().getId() != null)) {
					return certificate.getRevocationDataById(subXCV.getRFC().getId());
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
			throw new IllegalArgumentException(String.format("The provided DigestMatcherType '%s' is not supported!", digestMatcher.getType()));
		}
	}

	/**
	 * Checks if a valid revocation (RAC) has been found
	 *
	 * @param subXCV {@link XmlSubXCV} result to be checked
	 * @return TRUE if at least one valid RAC found, FALSE otherwise
	 */
	public static boolean isValidRACFound(XmlSubXCV subXCV) {
		for (XmlRAC rac : subXCV.getRAC()) {
			if (rac != null && rac.getConclusion() != null &&
					Indication.PASSED.equals(rac.getConclusion().getIndication())) {
				return true;
			}
		}
		return false;
	}

}
