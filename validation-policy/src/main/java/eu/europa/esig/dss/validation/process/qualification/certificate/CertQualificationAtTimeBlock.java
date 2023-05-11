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

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.CertificateQualifiedStatus;
import eu.europa.esig.dss.enumerations.CertificateType;
import eu.europa.esig.dss.enumerations.QSCDStatus;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.CaQcCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.CertificateIssuedByConsistentByQCTrustServiceCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.CertificateIssuedByConsistentByQSCDTrustServiceCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.CertificateTypeCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.CertificateTypeCoverageCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.GrantedStatusCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.IsAbleToSelectOneTrustService;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.IsNoQualificationConflictDetectedCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.QSCDCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.QualifiedCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.RelatedToMraEnactedTrustServiceCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.ServiceConsistencyCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.TrustServiceAtTimeCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.TrustServicesByCertificateTypeCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.TrustedCertificateMatchTrustServiceCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.ValidCAQCCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd.QSCDStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd.QSCDStrategyFactory;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qualified.QualificationStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qualified.QualificationStrategyFactory;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.type.TypeStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.type.TypeStrategyFactory;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedServiceFilter;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedServicesFilterFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Verifies certificate's qualification at the given time
 *
 */
public class CertQualificationAtTimeBlock extends Chain<XmlValidationCertificateQualification> {

	/** The time type to get the qualification at */
	private final ValidationTime validationTime;

	/** The time to check against */
	private final Date date;

	/** Certificate to get qualification for */
	private final CertificateWrapper signingCertificate;

	/** List of matching TrustedServices */
	private final List<TrustedServiceWrapper> acceptableServices;

	/** Internal cached variable, representing the qualification result */
	private CertificateQualification certificateQualification = CertificateQualification.NA;

	/**
	 * Constructor to instantiate the validation at the certificate's issuance time
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param validationTime {@link ValidationTime}
	 * @param signingCertificate {@link CertificateWrapper} to get qualification for
	 * @param acceptableServices list of {@link TrustedServiceWrapper}s
	 */
	public CertQualificationAtTimeBlock(I18nProvider i18nProvider, ValidationTime validationTime,
										CertificateWrapper signingCertificate, List<TrustedServiceWrapper> acceptableServices) {
		this(i18nProvider, validationTime, null, signingCertificate, acceptableServices);
	}

	/**
	 * Constructor to instantiate the validation at the validation time
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param validationTime {@link ValidationTime}
	 * @param date {@link Date}
	 * @param signingCertificate {@link CertificateWrapper} to get qualification for
	 * @param acceptableServices list of {@link TrustedServiceWrapper}s
	 */
	public CertQualificationAtTimeBlock(I18nProvider i18nProvider, ValidationTime validationTime, Date date,
										CertificateWrapper signingCertificate, List<TrustedServiceWrapper> acceptableServices) {
		super(i18nProvider, new XmlValidationCertificateQualification());
		result.setId(signingCertificate.getId());

		this.validationTime = validationTime;
		this.signingCertificate = signingCertificate;
		this.acceptableServices = new ArrayList<>(acceptableServices);

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
		MessageTag param = ValidationProcessUtils.getValidationTimeMessageTag(validationTime);
		return i18nProvider.getMessage(message, param);
	}

	@Override
	protected void initChain() {
		// Init internal variable to the provided list of extracted Trust Services
		List<TrustedServiceWrapper> filteredServices = new ArrayList<>(acceptableServices);

		ChainItem<XmlValidationCertificateQualification> item = null;

		// 1a. Filter by date
		TrustedServiceFilter filterByDate = TrustedServicesFilterFactory.createFilterByDate(date);
		filteredServices = filterByDate.filter(filteredServices);

		// Execute only for Trusted Lists with defined MRA
		if (isMRAEnactedForTrustedList(filteredServices)) {
			TrustedServiceFilter filterByMRAEnacted = TrustedServicesFilterFactory.createMRAEnactedFilter();
			filteredServices = filterByMRAEnacted.filter(filteredServices);

			filterByMRAEnacted = TrustedServicesFilterFactory.createFilterByMRAEquivalenceStartingDate(date);
			filteredServices = filterByMRAEnacted.filter(filteredServices);

			filterByMRAEnacted = TrustedServicesFilterFactory.createFilterByDate(date);
			filteredServices = filterByMRAEnacted.filter(filteredServices);

			item = firstItem = hasMraEnactedTrustService(filteredServices);

		} else {
			item = firstItem = hasTrustServiceAtTime(filteredServices);
		}

		// 1b. Filter by service for CA/QC
		TrustedServiceFilter filterByCaQc = TrustedServicesFilterFactory.createFilterByCaQc();
		List<TrustedServiceWrapper> caqcServices = filterByCaQc.filter(filteredServices);

		item = item.setNextItem(hasCaQc(filteredServices));

		// continue validation with available trust services if CA/QC not found
		if (Utils.isCollectionNotEmpty(caqcServices)) {
			filteredServices = caqcServices;
		}

		// 2. Filter by cert type (current type or overruled)
		TrustedServiceFilter filterByCertificateType = TrustedServicesFilterFactory.createFilterByCertificateType(signingCertificate);
		filteredServices = filterByCertificateType.filter(filteredServices);

		item = item.setNextItem(hasTrustServiceWithType(filteredServices));

		// 3. Run consistency checks to get warnings
		for (TrustedServiceWrapper trustedService : filteredServices) {
			item = item.setNextItem(serviceConsistency(trustedService));
		}

		if (filteredServices.size() > 1) {
			// 4. Simulate with all CA/QC (granted + withdrawn) to detect conflict
			Set<CertificateQualification> results = new HashSet<>();
			for (TrustedServiceWrapper trustedService : filteredServices) {
				CertificateQualificationCalculator calculator = new CertificateQualificationCalculator(signingCertificate, trustedService);
				results.add(calculator.getQualification());
			}
			item = item.setNextItem(isNoConflictDetected(results));

			// interrupt in case of conflict
			if (results.size() > 1) {
				certificateQualification = CertificateQualification.NA;
				return;
			}
		}

		// 5a. Filter services with consistent status
		TrustedServiceFilter filterConsistentByStatus = TrustedServicesFilterFactory.createConsistentServiceByStatusFilter();
		filteredServices = filterConsistentByStatus.filter(filteredServices);

		// 5b. Filter by Granted
		item = item.setNextItem(hasGrantedStatus(filteredServices));

		TrustedServiceFilter filterByGranted = TrustedServicesFilterFactory.createFilterByGranted();
		List<TrustedServiceWrapper> grantedServices = filterByGranted.filter(filteredServices);

		// continue validation with available trust services if granted not found
		if (Utils.isCollectionNotEmpty(grantedServices)) {
			filteredServices = grantedServices;
		}

		// 6. Filter one trust service
		if (Utils.collectionSize(filteredServices) > 1) {
			TrustedServiceFilter filterUnique = TrustedServicesFilterFactory.createUniqueServiceFilter(signingCertificate);
			filteredServices = filterUnique.filter(filteredServices);

			item = item.setNextItem(isAbleToSelectOneTrustService(filteredServices));
		}

		TrustedServiceWrapper selectedTrustService = !filteredServices.isEmpty() ? filteredServices.get(0) : null;

		// 7. Trusted certificate matches the trust service properties ?
		item = item.setNextItem(isTrustedCertificateMatchTrustService(selectedTrustService));

		// Keep only CA/QC and granted for further status determination
		if (!caqcServices.contains(selectedTrustService) || !grantedServices.contains(selectedTrustService)) {
			filteredServices = Collections.emptyList();
			selectedTrustService = null;
		}

		item = item.setNextItem(isValidCAQC(selectedTrustService));

		// 8. QC?
		TrustedServiceFilter filterConsistentByQC = TrustedServicesFilterFactory.createConsistentServiceByQCFilter();
		filteredServices = filterConsistentByQC.filter(filteredServices);

		item = item.setNextItem(hasConsistentByQCTrustService(filteredServices));

		selectedTrustService = !filteredServices.isEmpty() ? filteredServices.get(0) : null;

		QualificationStrategy qcStrategy = QualificationStrategyFactory.createQualificationFromCertAndTL(signingCertificate, selectedTrustService);
		CertificateQualifiedStatus qualifiedStatus = qcStrategy.getQualifiedStatus();
		item = item.setNextItem(isQualified(qualifiedStatus));

		// 9. Type?
		TrustedServiceFilter filterConsistentByType = TrustedServicesFilterFactory.createConsistentServiceByCertificateTypeFilter();
		List<TrustedServiceWrapper> caqcServicesByType = filterConsistentByType.filter(filteredServices);

		item = item.setNextItem(hasCertificateTypeCoverage(caqcServicesByType));

		selectedTrustService = !caqcServicesByType.isEmpty() ? caqcServicesByType.get(0) : null;

		TypeStrategy typeStrategy = TypeStrategyFactory.createTypeFromCertAndTL(signingCertificate, selectedTrustService, qualifiedStatus);
		CertificateType type = typeStrategy.getType();
		item = item.setNextItem(certificateType(type));

		// 11. QSCD ?
		TrustedServiceFilter filterConsistentByQSCD = TrustedServicesFilterFactory.createConsistentServiceByQSCDFilter();
		filteredServices = filterConsistentByQSCD.filter(filteredServices);

		item = item.setNextItem(hasConsistentByQSCDTrustService(filteredServices));

		selectedTrustService = !filteredServices.isEmpty() ? filteredServices.get(0) : null;

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

	private ChainItem<XmlValidationCertificateQualification> hasMraEnactedTrustService(List<TrustedServiceWrapper> trustServices) {
		return new RelatedToMraEnactedTrustServiceCheck<>(i18nProvider, result, trustServices, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> hasCaQc(List<TrustedServiceWrapper> trustServices) {
		return new CaQcCheck(i18nProvider, result, trustServices, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> hasTrustServiceAtTime(List<TrustedServiceWrapper> trustServices) {
		return new TrustServiceAtTimeCheck(i18nProvider, result, trustServices, validationTime, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> hasTrustServiceWithType(List<TrustedServiceWrapper> trustServices) {
		return new TrustServicesByCertificateTypeCheck(i18nProvider, result, trustServices, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> isNoConflictDetected(Set<CertificateQualification> certificateQualificationsAtTime) {
		return new IsNoQualificationConflictDetectedCheck(i18nProvider, result, certificateQualificationsAtTime, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> hasGrantedStatus(List<TrustedServiceWrapper> trustServices) {
		return new GrantedStatusCheck<>(i18nProvider, result, trustServices, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> hasCertificateTypeCoverage(
			List<TrustedServiceWrapper> trustServices) {
		return new CertificateTypeCoverageCheck(i18nProvider, result, trustServices, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> hasConsistentByQCTrustService(
			List<TrustedServiceWrapper> trustServices) {
		return new CertificateIssuedByConsistentByQCTrustServiceCheck(i18nProvider, result, trustServices, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> hasConsistentByQSCDTrustService(
			List<TrustedServiceWrapper> trustServices) {
		return new CertificateIssuedByConsistentByQSCDTrustServiceCheck(i18nProvider, result, trustServices, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> isAbleToSelectOneTrustService(List<TrustedServiceWrapper> trustServices) {
		return new IsAbleToSelectOneTrustService(i18nProvider, result, trustServices, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> serviceConsistency(TrustedServiceWrapper selectedTrustService) {
		return new ServiceConsistencyCheck(i18nProvider, result, selectedTrustService, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> isTrustedCertificateMatchTrustService(TrustedServiceWrapper selectedTrustService) {
		return new TrustedCertificateMatchTrustServiceCheck(i18nProvider, result, selectedTrustService, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> isValidCAQC(TrustedServiceWrapper selectedTrustService) {
		return new ValidCAQCCheck(i18nProvider, result, selectedTrustService, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> isQualified(CertificateQualifiedStatus qualifiedStatus) {
		return new QualifiedCheck(i18nProvider, result, qualifiedStatus, validationTime, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> certificateType(CertificateType type) {
		return new CertificateTypeCheck(i18nProvider, result, type, validationTime, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> isQscd(QSCDStatus qscdStatus) {
		return new QSCDCheck(i18nProvider, result, qscdStatus, validationTime, getWarnLevelConstraint());
	}

	private boolean isMRAEnactedForTrustedList(List<TrustedServiceWrapper> trustedServices) {
		for (TrustedServiceWrapper trustedService : trustedServices) {
			if (Utils.isTrue(trustedService.getTrustedList().isMra())) {
				return true;
			}
		}
		return false;
	}

}
