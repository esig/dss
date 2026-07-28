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
package eu.europa.esig.dss.validation.process.qualification.certificate;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
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
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.MRACertificateEquivalenceApplied;
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
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustServiceFilter;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustServicesFilterFactory;

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

	/** List of matching TrustServices */
	private final List<TrustServiceWrapper> acceptableServices;

	/** Internal cached variable, representing the qualification result */
	private CertificateQualification certificateQualification = CertificateQualification.NA;

	/** Internal cached variable, representing the filtered value trust services allowed to issue qualified certificates */
	private List<TrustServiceWrapper> filteredServices;

	/**
	 * Constructor to instantiate the validation at the certificate's issuance time
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param validationTime {@link ValidationTime}
	 * @param signingCertificate {@link CertificateWrapper} to get qualification for
	 * @param acceptableServices list of {@link TrustServiceWrapper}s
	 */
	public CertQualificationAtTimeBlock(I18nProvider i18nProvider, ValidationTime validationTime,
										CertificateWrapper signingCertificate, List<TrustServiceWrapper> acceptableServices) {
		this(i18nProvider, validationTime, null, signingCertificate, acceptableServices);
	}

	/**
	 * Constructor to instantiate the validation at the validation time
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param validationTime {@link ValidationTime}
	 * @param date {@link Date}
	 * @param signingCertificate {@link CertificateWrapper} to get qualification for
	 * @param acceptableServices list of {@link TrustServiceWrapper}s
	 */
	public CertQualificationAtTimeBlock(I18nProvider i18nProvider, ValidationTime validationTime, Date date,
										CertificateWrapper signingCertificate, List<TrustServiceWrapper> acceptableServices) {
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
		filteredServices = new ArrayList<>(acceptableServices);

		ChainItem<XmlValidationCertificateQualification> item = null;

		// 1a. Filter by date
		TrustServiceFilter filterByDate = TrustServicesFilterFactory.createFilterByDate(date);
		filteredServices = filterByDate.filter(filteredServices);

		// Execute only for Trusted Lists with defined MRA
		if (isMRAEnactedForTrustedList(filteredServices)) {
			TrustServiceFilter filterByMRAEnacted = TrustServicesFilterFactory.createMRAEnactedFilter();
			filteredServices = filterByMRAEnacted.filter(filteredServices);

			filterByMRAEnacted = TrustServicesFilterFactory.createFilterByMRAEquivalenceStartingDate(date);
			filteredServices = filterByMRAEnacted.filter(filteredServices);

			item = firstItem = hasMraEnactedTrustService(filteredServices);

			item = item.setNextItem(mraCertificateEquivalenceApplied());

		} else {
			item = firstItem = hasTrustServiceAtTime(filteredServices);
		}

		// 1b. Filter by service for CA/QC
		item = item.setNextItem(hasCaQc(filteredServices));

		TrustServiceFilter filterByCaQc = TrustServicesFilterFactory.createFilterByCaQc();
		List<TrustServiceWrapper> caqcServices = filterByCaQc.filter(filteredServices);

		// continue validation with available trust services if CA/QC not found
		if (Utils.isCollectionNotEmpty(caqcServices)) {
			filteredServices = caqcServices;
		}

		// 2. Filter by cert type (current type or overruled)
		TrustServiceFilter filterByCertificateType = TrustServicesFilterFactory.createFilterByCertificateType(signingCertificate);
		filteredServices = filterByCertificateType.filter(filteredServices);

		item = item.setNextItem(hasTrustServiceWithType(filteredServices));

		// 3. Run consistency checks to get warnings
		for (TrustServiceWrapper trustService : filteredServices) {
			item = item.setNextItem(serviceConsistency(trustService));
		}

		if (filteredServices.size() > 1) {
			// 4. Simulate with all CA/QC (granted + withdrawn) to detect conflict
			Set<CertificateQualification> results = new HashSet<>();
			for (TrustServiceWrapper trustService : filteredServices) {
				CertificateQualificationCalculator calculator = new CertificateQualificationCalculator(signingCertificate, trustService);
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
		TrustServiceFilter filterConsistentByStatus = TrustServicesFilterFactory.createConsistentServiceByStatusFilter();
		filteredServices = filterConsistentByStatus.filter(filteredServices);

		// 5b. Filter by Granted
		item = item.setNextItem(hasGrantedStatus(filteredServices));

		TrustServiceFilter filterByGranted = TrustServicesFilterFactory.createFilterByGranted();
		List<TrustServiceWrapper> grantedServices = filterByGranted.filter(filteredServices);

		// continue validation with available trust services if granted not found
		if (Utils.isCollectionNotEmpty(grantedServices)) {
			filteredServices = grantedServices;
		}

		// 6. Filter one trust service
		if (Utils.collectionSize(filteredServices) > 1) {
			TrustServiceFilter filterUnique = TrustServicesFilterFactory.createUniqueServiceFilter(signingCertificate);
			filteredServices = filterUnique.filter(filteredServices);

			item = item.setNextItem(isAbleToSelectOneTrustService(filteredServices));
		}

		TrustServiceWrapper selectedTrustService = !filteredServices.isEmpty() ? filteredServices.get(0) : null;

		// 7. Trusted certificate matches the trust service properties ?
		if (selectedTrustService != null) {
			item = item.setNextItem(isTrustedCertificateMatchTrustService(selectedTrustService));
		}

		// Keep only CA/QC and granted for further status determination
		if (!caqcServices.contains(selectedTrustService) || !grantedServices.contains(selectedTrustService)) {
			filteredServices = Collections.emptyList();
			selectedTrustService = null;
		}

		item = item.setNextItem(isValidCAQC(selectedTrustService));

		// 8. QC?
		TrustServiceFilter filterConsistentByQC = TrustServicesFilterFactory.createConsistentServiceByQCFilter();
		List<TrustServiceWrapper> trustServicesByQC = filterConsistentByQC.filter(filteredServices);

		item = item.setNextItem(hasConsistentByQCTrustService(trustServicesByQC));

		selectedTrustService = !trustServicesByQC.isEmpty() ? trustServicesByQC.get(0) : null;

		QualificationStrategy qcStrategy = QualificationStrategyFactory.createQualificationFromCertAndTL(signingCertificate, selectedTrustService);
		CertificateQualifiedStatus qualifiedStatus = qcStrategy.getQualifiedStatus();
		item = item.setNextItem(isQualified(qualifiedStatus));

		// 9. Type?
		TrustServiceFilter filterConsistentByType = TrustServicesFilterFactory.createConsistentServiceByCertificateTypeFilter();
		List<TrustServiceWrapper> trustServicesByType = filterConsistentByType.filter(filteredServices);

		item = item.setNextItem(hasCertificateTypeCoverage(trustServicesByType));

		selectedTrustService = !trustServicesByType.isEmpty() ? trustServicesByType.get(0) : null;

		TypeStrategy typeStrategy = TypeStrategyFactory.createTypeFromCertAndTL(signingCertificate, selectedTrustService, qualifiedStatus);
		CertificateType type = typeStrategy.getType();
		item = item.setNextItem(certificateType(type));

		// 11. QSCD ?
		TrustServiceFilter filterConsistentByQSCD = TrustServicesFilterFactory.createConsistentServiceByQSCDFilter();
		List<TrustServiceWrapper> trustServicesByQSCD = filterConsistentByQSCD.filter(filteredServices);

		selectedTrustService = !trustServicesByQSCD.isEmpty() ? trustServicesByQSCD.get(0) : null;

		QSCDStrategy qscdStrategy = QSCDStrategyFactory.createQSCDFromCertAndTL(signingCertificate, selectedTrustService, qualifiedStatus);
		QSCDStatus qscdStatus = qscdStrategy.getQSCDStatus();

		if (executeQSCDCheck()) {

			item = item.setNextItem(hasConsistentByQSCDTrustService(trustServicesByQSCD));

			item = item.setNextItem(isQscd(qscdStatus));

		}

		certificateQualification = CertQualificationMatrix.getCertQualification(qualifiedStatus, type, qscdStatus);

	}

	/**
	 * Returns a list of filtered valid trust services allowed to issue qualified certificates
	 *
	 * @return list of {@link TrustServiceWrapper}s
	 */
	public List<TrustServiceWrapper> getFilteredServices() {
		if (filteredServices == null) {
			throw new IllegalStateException("execute() method shall be called first!");
		}
		return filteredServices;
	}

	@Override
	protected void addAdditionalInfo() {
		result.setCertificateQualification(certificateQualification);
		result.setValidationTime(validationTime);
		result.setDateTime(date);
	}

	private ChainItem<XmlValidationCertificateQualification> hasMraEnactedTrustService(List<TrustServiceWrapper> trustServices) {
		return new RelatedToMraEnactedTrustServiceCheck<>(i18nProvider, result, trustServices, getFailLevelRule());
	}

	private ChainItem<XmlValidationCertificateQualification> mraCertificateEquivalenceApplied() {
		return new MRACertificateEquivalenceApplied<>(i18nProvider, result, signingCertificate, getWarnLevelRule());
	}

	private ChainItem<XmlValidationCertificateQualification> hasCaQc(List<TrustServiceWrapper> trustServices) {
		return new CaQcCheck(i18nProvider, result, trustServices, getWarnLevelRule());
	}

	private ChainItem<XmlValidationCertificateQualification> hasTrustServiceAtTime(List<TrustServiceWrapper> trustServices) {
		return new TrustServiceAtTimeCheck(i18nProvider, result, trustServices, validationTime, getFailLevelRule());
	}

	private ChainItem<XmlValidationCertificateQualification> hasTrustServiceWithType(List<TrustServiceWrapper> trustServices) {
		return new TrustServicesByCertificateTypeCheck(i18nProvider, result, trustServices, getFailLevelRule());
	}

	private ChainItem<XmlValidationCertificateQualification> isNoConflictDetected(Set<CertificateQualification> certificateQualificationsAtTime) {
		return new IsNoQualificationConflictDetectedCheck(i18nProvider, result, certificateQualificationsAtTime, getFailLevelRule());
	}

	private ChainItem<XmlValidationCertificateQualification> hasGrantedStatus(List<TrustServiceWrapper> trustServices) {
		return new GrantedStatusCheck<>(i18nProvider, result, trustServices, getWarnLevelRule());
	}

	private ChainItem<XmlValidationCertificateQualification> hasCertificateTypeCoverage(
			List<TrustServiceWrapper> trustServices) {
		return new CertificateTypeCoverageCheck(i18nProvider, result, trustServices, getFailLevelRule());
	}

	private ChainItem<XmlValidationCertificateQualification> hasConsistentByQCTrustService(
			List<TrustServiceWrapper> trustServices) {
		return new CertificateIssuedByConsistentByQCTrustServiceCheck(i18nProvider, result, trustServices, getFailLevelRule());
	}

	private ChainItem<XmlValidationCertificateQualification> hasConsistentByQSCDTrustService(
			List<TrustServiceWrapper> trustServices) {
		return new CertificateIssuedByConsistentByQSCDTrustServiceCheck(i18nProvider, result, trustServices, getFailLevelRule());
	}

	private ChainItem<XmlValidationCertificateQualification> isAbleToSelectOneTrustService(List<TrustServiceWrapper> trustServices) {
		return new IsAbleToSelectOneTrustService(i18nProvider, result, trustServices, getFailLevelRule());
	}

	private ChainItem<XmlValidationCertificateQualification> serviceConsistency(TrustServiceWrapper selectedTrustService) {
		return new ServiceConsistencyCheck(i18nProvider, result, selectedTrustService, getWarnLevelRule());
	}

	private ChainItem<XmlValidationCertificateQualification> isTrustedCertificateMatchTrustService(TrustServiceWrapper selectedTrustService) {
		return new TrustedCertificateMatchTrustServiceCheck(i18nProvider, result, selectedTrustService, getWarnLevelRule());
	}

	private ChainItem<XmlValidationCertificateQualification> isValidCAQC(TrustServiceWrapper selectedTrustService) {
		return new ValidCAQCCheck(i18nProvider, result, selectedTrustService, getFailLevelRule());
	}

	private ChainItem<XmlValidationCertificateQualification> isQualified(CertificateQualifiedStatus qualifiedStatus) {
		return new QualifiedCheck(i18nProvider, result, qualifiedStatus, validationTime, getWarnLevelRule());
	}

	private ChainItem<XmlValidationCertificateQualification> certificateType(CertificateType type) {
		return new CertificateTypeCheck(i18nProvider, result, type, validationTime, getWarnLevelRule());
	}

	private ChainItem<XmlValidationCertificateQualification> isQscd(QSCDStatus qscdStatus) {
		return new QSCDCheck(i18nProvider, result, qscdStatus, validationTime, getWarnLevelRule());
	}

	/**
	 * This method defines whether a QSCD check should be processed for certificate qualification determination.
	 * NOTE: Can be disabled in some cases, e.g. for QWAC validation
	 *
	 * @return whether QSCD check should be executed
	 */
	protected boolean executeQSCDCheck() {
		return true;
	}

	private boolean isMRAEnactedForTrustedList(List<TrustServiceWrapper> trustServices) {
		for (TrustServiceWrapper trustService : trustServices) {
			if (Utils.isTrue(trustService.getTrustedList().isMra())) {
				return true;
			}
		}
		return false;
	}

}
