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
package eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

/**
 * Checks if the revocation is consistent and can be used for the given certificate
 *
 * @param <T> {@link XmlConstraintsConclusion}
 */
public class RevocationConsistentCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	private static final Logger LOG = LoggerFactory.getLogger(RevocationConsistentCheck.class);

	/** The certificate in question */
	protected final CertificateWrapper certificate;

	/** Revocation data to check */
	protected final RevocationWrapper revocationData;

	/** ThisUpdate of the revocation */
	protected Date thisUpdate;

	/** ProducedAt time of the revocation */
	protected Date producedAt;

	/** Certificate's NotBefore */
	protected Date certNotBefore;

	/** Certificate's NotAfter */
	protected Date certNotAfter;

	/** Defines date after which the revocation issuer ensure the revocation is contained for the certificate */
	protected Date notAfterRevoc;

	/** Defines if certHash matches */
	protected boolean certHashOK;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param certificate {@link CertificateWrapper}
	 * @param revocationData {@link RevocationWrapper}
	 * @param constraint {@link LevelConstraint}
	 */
	public RevocationConsistentCheck(I18nProvider i18nProvider, T result, CertificateWrapper certificate, 
			RevocationWrapper revocationData, LevelConstraint constraint) {
		super(i18nProvider, result, constraint, revocationData.getId());
		this.certificate = certificate;
		this.revocationData = revocationData;
	}

	@Override
	protected XmlBlockType getBlockType() {
		return XmlBlockType.REV_CC;
	}

	@Override
	protected boolean process() {
		certNotBefore = certificate.getNotBefore();
		certNotAfter = certificate.getNotAfter();
		thisUpdate = revocationData.getThisUpdate();
		producedAt = revocationData.getProductionDate();

		notAfterRevoc = thisUpdate;

		/*
		 * If a CRL contains the extension expiredCertsOnCRL defined in [i.12], it shall prevail over the TL
		 * extension value but only for that specific CRL.
		 */
		Date expiredCertsOnCRL = revocationData.getExpiredCertsOnCRL();
		if (expiredCertsOnCRL != null) {
			if (expiredCertsOnCRL.before(notAfterRevoc)) {
				notAfterRevoc = expiredCertsOnCRL;
			} else {
				LOG.info("ExpiredCertsOnCRL : '{}' is not before revocation's thisUpdate : '{}'.",
						ValidationProcessUtils.getFormattedDate(expiredCertsOnCRL), ValidationProcessUtils.getFormattedDate(notAfterRevoc));
			}
		}

		/*
		 * If an OCSP response contains the extension ArchiveCutoff defined in section 4.4.4 of
		 * IETF RFC 6960 [i.11], it shall prevail over the TL extension value but only for that specific OCSP
		 * response.
		 */
		Date archiveCutOff = revocationData.getArchiveCutOff();
		if (archiveCutOff != null) {
			if (archiveCutOff.before(notAfterRevoc)) {
				notAfterRevoc = archiveCutOff;
			} else {
				LOG.info("ArchiveCutoff : '{}' is not before revocation's thisUpdate : '{}'.",
						ValidationProcessUtils.getFormattedDate(archiveCutOff), ValidationProcessUtils.getFormattedDate(notAfterRevoc));
			}
		}

		/* expiredCertsRevocationInfo Extension from TL */
		if (expiredCertsOnCRL == null && archiveCutOff == null) {
			Date expiredCertsRevocationInfo = getExpiredCertsRevocationInfo(revocationData);
			if (expiredCertsRevocationInfo != null) {
				if (expiredCertsRevocationInfo.before(notAfterRevoc)) {
					notAfterRevoc = expiredCertsRevocationInfo;
				} else {
					LOG.info("ExpiredCertsRevocationInfo : '{}' is not before revocation's thisUpdate : '{}'.",
							ValidationProcessUtils.getFormattedDate(expiredCertsRevocationInfo), ValidationProcessUtils.getFormattedDate(notAfterRevoc));
				}
			}
		}

		/*
		 * certHash extension can be present in an OCSP Response. If present, a digest match indicates the OCSP
		 * responder knows the certificate as we have it, and so also its revocation state
		 */
		certHashOK = revocationData.isCertHashExtensionPresent() && revocationData.isCertHashExtensionMatch();

		return checkThisUpdateDefined() && checkRevocationDataHasInformationAboutCertificate() &&
				checkIssuerKnowsCertificate() && checkRevocationIssuerKnown() &&
				checkIssuerValidAtProductionTime();
	}

	private Date getExpiredCertsRevocationInfo(RevocationWrapper revocationData) {
		CertificateWrapper revocCert = revocationData.getSigningCertificate();
		if (revocCert != null) {
			return revocCert.getCertificateTSPServiceExpiredCertsRevocationInfo();
		}
		return null;
	}

	private boolean checkThisUpdateDefined() {
		return thisUpdate != null;
	}

	private boolean checkRevocationDataHasInformationAboutCertificate() {
		return certNotBefore.compareTo(thisUpdate) <= 0;
	}

	private boolean checkIssuerKnowsCertificate() {
		return checkIssuerHasInformationForExpiredCertificate() || checkCertHashMatches();
	}

	private boolean checkIssuerHasInformationForExpiredCertificate() {
		return certNotAfter.compareTo(notAfterRevoc) >= 0;
	}

	private boolean checkCertHashMatches() {
		return certHashOK;
	}

	private boolean checkRevocationIssuerKnown() {
		return revocationData.getSigningCertificate() != null;
	}

	private boolean checkIssuerValidAtProductionTime() {
		// check performed only for OCSP certificates
		return !RevocationType.OCSP.equals(revocationData.getRevocationType()) ||
				checkOCSPResponderValidAtRevocationProductionTime();
	}

	private boolean checkOCSPResponderValidAtRevocationProductionTime() {
		CertificateWrapper revocationIssuer = revocationData.getSigningCertificate();
		return producedAt.compareTo(revocationIssuer.getNotBefore()) >= 0 &&
						producedAt.compareTo(revocationIssuer.getNotAfter()) <= 0;
	}

	private boolean checkRevocationThisUpdateIsInCertificateValidityRange() {
		return revocationData.getThisUpdate().compareTo(certNotBefore) >= 0 &&
				revocationData.getThisUpdate().compareTo(certNotAfter) <= 0;
	}

	private boolean checkExpiredCertsOnCRLPresent() {
		return revocationData.getExpiredCertsOnCRL() != null;
	}

	private boolean checkArchiveCutOffPresent() {
		return revocationData.getArchiveCutOff() != null;
	}

	private boolean checkExpiredCertsRevocationInfoPresent() {
		return getExpiredCertsRevocationInfo(revocationData) != null;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_IRDC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_IRDC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE;
	}

	@Override
	protected String buildAdditionalInfo() {
		if (!checkThisUpdateDefined()) {
			return getNoThisUpdateMessage();

		} else if (!checkRevocationDataHasInformationAboutCertificate()) {
			return getThisUpdateBeforeCertificateNotBeforeMessage();

		} else if (!checkIssuerKnowsCertificate()) {
			return getNotAfterAfterCertificateNotAfterMessage();

		} else if (!checkRevocationIssuerKnown()) {
			return getRevocationIssuerNotFoundMessage();

		} else if (!checkIssuerValidAtProductionTime()) {
			return getRevocationProducesAtOutOfBoundsMessage();

		} else if (checkRevocationThisUpdateIsInCertificateValidityRange()) {
			return getRevocationConsistentMessage();

		} else if (checkCertHashMatches()) {
			return getRevocationCertHashOkMessage();

		} else if (checkExpiredCertsOnCRLPresent()) {
			return getRevocationConsistentWithExpiredCertsOnCRLMessage();

		} else if (checkArchiveCutOffPresent()) {
			return getRevocationConsistentWithArchiveCutoffMessage();

		} else if (checkExpiredCertsRevocationInfoPresent()) {
			return getRevocationConsistentWithExpiredCertsRevocationInfoMessage();

		} else {
			return getRevocationInfoMessage();
		}
	}

	/**
	 * Returns the additional information message in case of no thisUpdate field defined
	 *
	 * @return {@link String}
	 */
	protected String getNoThisUpdateMessage() {
		return i18nProvider.getMessage(MessageTag.REVOCATION_NO_THIS_UPDATE);
	}

	/**
	 * Returns the additional information message in case if thisUpdate is before certificate's notBefore
	 *
	 * @return {@link String}
	 */
	protected String getThisUpdateBeforeCertificateNotBeforeMessage() {
		return i18nProvider.getMessage(MessageTag.REVOCATION_THIS_UPDATE_BEFORE,
				ValidationProcessUtils.getFormattedDate(thisUpdate),
				ValidationProcessUtils.getFormattedDate(certNotBefore),
				ValidationProcessUtils.getFormattedDate(certNotAfter));
	}

	/**
	 * Returns the additional information message in case if
	 * computed time 'notAfter' is after the certificate's notAfter
	 *
	 * @return {@link String}
	 */
	protected String getNotAfterAfterCertificateNotAfterMessage() {
		return i18nProvider.getMessage(MessageTag.REVOCATION_NOT_AFTER_AFTER,
				ValidationProcessUtils.getFormattedDate(notAfterRevoc),
				ValidationProcessUtils.getFormattedDate(certNotBefore),
				ValidationProcessUtils.getFormattedDate(certNotAfter));
	}

	/**
	 * Returns the additional information message when revocation's issue is not found
	 *
	 * @return {@link String}
	 */
	protected String getRevocationIssuerNotFoundMessage() {
		return i18nProvider.getMessage(MessageTag.REVOCATION_ISSUER_NOT_FOUND);
	}

	/**
	 * Returns the additional information message when revocation has been produced at out of
	 * the signing certificate's validity
	 *
	 * @return {@link String}
	 */
	protected String getRevocationProducesAtOutOfBoundsMessage() {
		return i18nProvider.getMessage(MessageTag.REVOCATION_PRODUCED_AT_OUT_OF_BOUNDS,
				ValidationProcessUtils.getFormattedDate(producedAt),
				ValidationProcessUtils.getFormattedDate(revocationData.getSigningCertificate().getNotBefore()),
				ValidationProcessUtils.getFormattedDate(revocationData.getSigningCertificate().getNotAfter()));
	}

	/**
	 * Returns the additional information message when certHash matches
	 *
	 * @return {@link String}
	 */
	protected String getRevocationCertHashOkMessage() {
		return i18nProvider.getMessage(MessageTag.REVOCATION_CERT_HASH_OK);
	}

	/**
	 * Returns the additional information message when the revocation is consistent
	 *
	 * @return {@link String}
	 */
	protected String getRevocationConsistentMessage() {
		return i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT,
				ValidationProcessUtils.getFormattedDate(thisUpdate),
				ValidationProcessUtils.getFormattedDate(certNotBefore),
				ValidationProcessUtils.getFormattedDate(certNotAfter));
	}

	/**
	 * Returns the additional information message when the revocation is consistent with expiredCertsOnCRL
	 *
	 * @return {@link String}
	 */
	protected String getRevocationConsistentWithExpiredCertsOnCRLMessage() {
		return i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT_CRL,
				ValidationProcessUtils.getFormattedDate(thisUpdate),
				ValidationProcessUtils.getFormattedDate(revocationData.getExpiredCertsOnCRL()),
				ValidationProcessUtils.getFormattedDate(certNotBefore),
				ValidationProcessUtils.getFormattedDate(certNotAfter));
	}

	/**
	 * Returns the additional information message when the revocation is consistent with archiveCutoff
	 *
	 * @return {@link String}
	 */
	protected String getRevocationConsistentWithArchiveCutoffMessage() {
		return i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT_OCSP,
				ValidationProcessUtils.getFormattedDate(thisUpdate),
				ValidationProcessUtils.getFormattedDate(revocationData.getArchiveCutOff()),
				ValidationProcessUtils.getFormattedDate(certNotBefore),
				ValidationProcessUtils.getFormattedDate(certNotAfter));
	}

	/**
	 * Returns the additional information message when the revocation is consistent with archiveCutoff
	 *
	 * @return {@link String}
	 */
	protected String getRevocationConsistentWithExpiredCertsRevocationInfoMessage() {
		return i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT_TL,
				ValidationProcessUtils.getFormattedDate(thisUpdate),
				ValidationProcessUtils.getFormattedDate(getExpiredCertsRevocationInfo(revocationData)),
				ValidationProcessUtils.getFormattedDate(certNotBefore),
				ValidationProcessUtils.getFormattedDate(certNotAfter));
	}

	/**
	 * Returns the additional information message for revocation data in case of other events
	 *
	 * @return {@link String}
	 */
	protected String getRevocationInfoMessage() {
		return i18nProvider.getMessage(MessageTag.REVOCATION_INFO,
				ValidationProcessUtils.getFormattedDate(thisUpdate),
				ValidationProcessUtils.getFormattedDate(certNotBefore),
				ValidationProcessUtils.getFormattedDate(certNotAfter));
	}

}
