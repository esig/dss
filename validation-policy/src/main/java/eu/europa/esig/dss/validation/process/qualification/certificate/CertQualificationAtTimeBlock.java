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
package eu.europa.esig.dss.validation.process.qualification.certificate;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.CaQcCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.CertificateIssuedByConsistentTrustServiceCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.CertificateTypeCoverageCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.ForEsigCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.GrantedStatusCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.IsAbleToSelectOneTrustService;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.IsQualificationConflictDetected;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.QSCDCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.QualifiedCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.ServiceConsistencyCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.TrustedCertificateMatchTrustServiceCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd.QSCDStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd.QSCDStrategyFactory;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qualified.QualificationStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qualified.QualificationStrategyFactory;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.type.TypeStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.type.TypeStrategyFactory;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedServiceFilter;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedServicesFilterFactory;

public class CertQualificationAtTimeBlock extends Chain<XmlValidationCertificateQualification> {

	private final ValidationTime validationTime;
	private final Date date;
	private final CertificateWrapper signingCertificate;
	private final List<TrustedServiceWrapper> caqcServices;

	private CertificateQualification certificateQualification = CertificateQualification.NA;

	public CertQualificationAtTimeBlock(I18nProvider i18nProvider, ValidationTime validationTime, CertificateWrapper signingCertificate,
			List<TrustedServiceWrapper> caqcServices) {
		this(i18nProvider, validationTime, null, signingCertificate, caqcServices);
	}

	public CertQualificationAtTimeBlock(I18nProvider i18nProvider, ValidationTime validationTime, Date date, CertificateWrapper signingCertificate,
			List<TrustedServiceWrapper> caqcServices) {
		super(i18nProvider, new XmlValidationCertificateQualification());
		result.setId(signingCertificate.getId());

		this.validationTime = validationTime;
		this.signingCertificate = signingCertificate;
		this.caqcServices = new ArrayList<>(caqcServices);

		switch (validationTime) {
		case CERTIFICATE_ISSUANCE_TIME:
			this.date = signingCertificate.getNotBefore();
			break;
		case VALIDATION_TIME:
		case BEST_SIGNATURE_TIME:
			this.date = date;
			break;
		default:
			throw new IllegalArgumentException("Unknown qualification time : " + validationTime);
		}
	}

	@Override
	protected String buildChainTitle() {
		MessageTag message = MessageTag.CERT_QUALIFICATION_AT_TIME;
		MessageTag param;
		switch (validationTime) {
		case BEST_SIGNATURE_TIME:
			param = MessageTag.VT_BEST_SIGNATURE_TIME;
			break;
		case CERTIFICATE_ISSUANCE_TIME:
			param = MessageTag.VT_CERTIFICATE_ISSUANCE_TIME;
			break;
		case VALIDATION_TIME:
			param = MessageTag.VT_VALIDATION_TIME;
			break;
		default:
			throw new IllegalArgumentException(String.format("The validation time [%s] is not supported", validationTime));
		}
		return i18nProvider.getMessage(message, param);
	}

	@Override
	protected void initChain() {

		// 1. Filter by date
		TrustedServiceFilter filterByDate = TrustedServicesFilterFactory.createFilterByDate(date);
		List<TrustedServiceWrapper> caqcServicesAtTime = filterByDate.filter(caqcServices);

		ChainItem<XmlValidationCertificateQualification> item = firstItem = item = hasCaQc(caqcServicesAtTime);

		// 2. Run consistency checks to get warnings
		for (TrustedServiceWrapper trustedService : caqcServicesAtTime) {
			item = item.setNextItem(serviceConsistency(trustedService));
		}

		if (caqcServicesAtTime.size() > 1) {
			// 3. Simulate with all CA/QC (granted + withdrawn) to detect conflict
			Set<CertificateQualification> results = new HashSet<>();
			for (TrustedServiceWrapper trustedService : caqcServicesAtTime) {
				CertificateQualificationCalculation calculator = new CertificateQualificationCalculation(signingCertificate, trustedService);
				results.add(calculator.getQualification());
			}
			item = item.setNextItem(isConflictDetected(results));

			// interrupt in case of conflict
			if (results.size() > 1) {
				certificateQualification = CertificateQualification.NA;
				return;
			}
		}

		// 4. Filter by Granted
		TrustedServiceFilter filterByGranted = TrustedServicesFilterFactory.createFilterByGranted();
		caqcServicesAtTime = filterByGranted.filter(caqcServicesAtTime);

		item = item.setNextItem(hasGrantedStatus(caqcServicesAtTime));

		// 5. Filter inconsistent trust services
		TrustedServiceFilter filterConsistent = TrustedServicesFilterFactory.createConsistentServiceFilter();
		caqcServicesAtTime = filterConsistent.filter(caqcServicesAtTime);

		item = item.setNextItem(hasConsistentTrustService(caqcServicesAtTime));

		// 6. Filter by certificate type (ASi or overruled)
		TrustedServiceFilter filterByCertificateType = TrustedServicesFilterFactory
				.createFilterByCertificateType(signingCertificate);
		caqcServicesAtTime = filterByCertificateType.filter(caqcServicesAtTime);

		item = item.setNextItem(hasCertificateTypeCoverage(caqcServicesAtTime));

		if (Utils.collectionSize(caqcServicesAtTime) > 1) {

			// 7. Filter one trust service
			TrustedServiceFilter filterUnique = TrustedServicesFilterFactory.createUniqueServiceFilter(signingCertificate);
			caqcServicesAtTime = filterUnique.filter(caqcServicesAtTime);

			item = item.setNextItem(isAbleToSelectOneTrustService(caqcServicesAtTime));
		}

		TrustedServiceWrapper selectedTrustService = !caqcServicesAtTime.isEmpty() ? caqcServicesAtTime.get(0) : null;

		// 8. Trusted certificate matches the trust service properties ?
		item = item.setNextItem(isTrustedCertificateMatchTrustService(selectedTrustService));

		// 9. QC?
		QualificationStrategy qcStrategy = QualificationStrategyFactory.createQualificationFromCertAndTL(signingCertificate, selectedTrustService);
		QualifiedStatus qualifiedStatus = qcStrategy.getQualifiedStatus();
		item = item.setNextItem(isQualified(qualifiedStatus));

		// 10. Type?
		TypeStrategy typeStrategy = TypeStrategyFactory.createTypeFromCertAndTL(signingCertificate, selectedTrustService, qualifiedStatus);
		Type type = typeStrategy.getType();
		item = item.setNextItem(isForEsig(type));

		// 11. QSCD ?
		QSCDStrategy qscdStrategy = QSCDStrategyFactory.createQSCDFromCertAndTL(signingCertificate, selectedTrustService, qualifiedStatus);
		QSCDStatus qscdStatus = qscdStrategy.getQSCDStatus();
		item = item.setNextItem(isQscd(qscdStatus));

		certificateQualification = CertQualificationMatrix.getCertQualification(qualifiedStatus, type, qscdStatus);

	}

	@Override
	protected void addAdditionalInfo() {
		result.setCertificateQualification(certificateQualification);
		result.setValidationTime(validationTime);
		result.setDateTime(date);
	}

	private ChainItem<XmlValidationCertificateQualification> hasCaQc(List<TrustedServiceWrapper> caqcServicesAtTime) {
		return new CaQcCheck(i18nProvider, result, caqcServicesAtTime, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> isConflictDetected(Set<CertificateQualification> certificateQualificationsAtTime) {
		return new IsQualificationConflictDetected(i18nProvider, result, certificateQualificationsAtTime, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> hasGrantedStatus(List<TrustedServiceWrapper> caqcServicesAtTime) {
		return new GrantedStatusCheck<>(i18nProvider, result, caqcServicesAtTime, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> hasCertificateTypeCoverage(
			List<TrustedServiceWrapper> caqcServicesAtTime) {
		return new CertificateTypeCoverageCheck(i18nProvider, result, caqcServicesAtTime, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> hasConsistentTrustService(
			List<TrustedServiceWrapper> caqcServicesAtTime) {
		return new CertificateIssuedByConsistentTrustServiceCheck(i18nProvider, result, caqcServicesAtTime, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> isAbleToSelectOneTrustService(List<TrustedServiceWrapper> caqcServicesAtTime) {
		return new IsAbleToSelectOneTrustService(i18nProvider, result, caqcServicesAtTime, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> serviceConsistency(TrustedServiceWrapper selectedTrustService) {
		return new ServiceConsistencyCheck(i18nProvider, result, selectedTrustService, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> isTrustedCertificateMatchTrustService(TrustedServiceWrapper selectedTrustService) {
		return new TrustedCertificateMatchTrustServiceCheck(i18nProvider, result, selectedTrustService, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> isQualified(QualifiedStatus qualifiedStatus) {
		return new QualifiedCheck(i18nProvider, result, qualifiedStatus, validationTime, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> isForEsig(Type type) {
		return new ForEsigCheck(i18nProvider, result, type, validationTime, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> isQscd(QSCDStatus qscdStatus) {
		return new QSCDCheck(i18nProvider, result, qscdStatus, validationTime, getWarnLevelConstraint());
	}

}
