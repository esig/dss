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
import java.util.List;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationCertificateQualification;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateQualification;
import eu.europa.esig.dss.validation.ValidationTime;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.CaQcCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.CertificateIssuedByConsistentTrustServiceCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.CertificateTypeCoverageCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.ForEsigCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.GrantedStatusCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.IsAbleToSelectOneTrustService;
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
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class CertQualificationAtTimeBlock extends Chain<XmlValidationCertificateQualification> {

	private final ValidationTime validationTime;
	private final Date date;
	private final CertificateWrapper signingCertificate;
	private final List<CertificateWrapper> usedCertificates;
	private final List<TrustedServiceWrapper> caqcServices;

	private CertificateQualification certificateQualification = CertificateQualification.NA;

	public CertQualificationAtTimeBlock(ValidationTime validationTime, CertificateWrapper signingCertificate, List<CertificateWrapper> usedCertificates,
			List<TrustedServiceWrapper> caqcServices) {
		this(validationTime, null, signingCertificate, usedCertificates, caqcServices);
	}

	public CertQualificationAtTimeBlock(ValidationTime validationTime, Date date, CertificateWrapper signingCertificate,
			List<CertificateWrapper> usedCertificates, List<TrustedServiceWrapper> caqcServices) {
		super(new XmlValidationCertificateQualification());

		this.validationTime = validationTime;
		this.signingCertificate = signingCertificate;
		this.usedCertificates = usedCertificates;
		this.caqcServices = new ArrayList<TrustedServiceWrapper>(caqcServices);

		switch (validationTime) {
		case CERTIFICATE_ISSUANCE_TIME:
			this.date = signingCertificate.getNotBefore();
			break;
		case VALIDATION_TIME:
		case BEST_SIGNATURE_TIME:
			this.date = date;
			break;
		default:
			throw new DSSException("Unknown qualification time : " + validationTime);
		}
	}

	@Override
	protected void initChain() {

		// 1. Filter by date
		TrustedServiceFilter filterByDate = TrustedServicesFilterFactory.createFilterByDate(date);
		List<TrustedServiceWrapper> caqcServicesAtTime = filterByDate.filter(caqcServices);

		ChainItem<XmlValidationCertificateQualification> item = firstItem = item = hasCaQc(caqcServicesAtTime);

		// 2. Filter by Granted
		TrustedServiceFilter filterByGranted = TrustedServicesFilterFactory.createFilterByGranted();
		caqcServicesAtTime = filterByGranted.filter(caqcServicesAtTime);

		item = item.setNextItem(hasGrantedStatus(caqcServicesAtTime));

		// 3.a Run consistency checks to get warnings
		for (TrustedServiceWrapper trustedService : caqcServicesAtTime) {
			item = item.setNextItem(serviceConsistency(trustedService));
		}

		// 3.b Filter inconsistent trust services
		TrustedServiceFilter filterConsistent = TrustedServicesFilterFactory.createConsistentServiceFilter();
		caqcServicesAtTime = filterConsistent.filter(caqcServicesAtTime);

		item = item.setNextItem(hasConsistentTrustService(caqcServicesAtTime));

		// 4. Filter by certificate type (ASi or overruled)
		TrustedServiceFilter filterByCertificateType = TrustedServicesFilterFactory
				.createFilterByCertificateType(signingCertificate);
		caqcServicesAtTime = filterByCertificateType.filter(caqcServicesAtTime);

		item = item.setNextItem(hasCertificateTypeCoverage(caqcServicesAtTime));

		if (Utils.collectionSize(caqcServicesAtTime) > 1) {

			// 5 Filter one trust service
			TrustedServiceFilter filterUnique = TrustedServicesFilterFactory.createUniqueServiceFilter(signingCertificate);
			caqcServicesAtTime = filterUnique.filter(caqcServicesAtTime);

			item = item.setNextItem(isAbleToSelectOneTrustService(caqcServicesAtTime));
		}

		TrustedServiceWrapper selectedTrustService = !caqcServicesAtTime.isEmpty() ? caqcServicesAtTime.get(0) : null;

		// 6. Trusted certificate matches the trust service properties ?
		item = item.setNextItem(isTrustedCertificateMatchTrustService(selectedTrustService));

		// 7. QC?
		QualificationStrategy qcStrategy = QualificationStrategyFactory.createQualificationFromCertAndTL(signingCertificate, selectedTrustService);
		QualifiedStatus qualifiedStatus = qcStrategy.getQualifiedStatus();
		item = item.setNextItem(isQualified(qualifiedStatus));

		// 8. Type?
		TypeStrategy typeStrategy = TypeStrategyFactory.createTypeFromCertAndTL(signingCertificate, selectedTrustService, qualifiedStatus);
		Type type = typeStrategy.getType();
		item = item.setNextItem(isForEsig(type));

		// 9. QSCD ?
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
		return new CaQcCheck(result, caqcServicesAtTime, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> hasGrantedStatus(List<TrustedServiceWrapper> caqcServicesAtTime) {
		return new GrantedStatusCheck(result, caqcServicesAtTime, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> hasCertificateTypeCoverage(
			List<TrustedServiceWrapper> caqcServicesAtTime) {
		return new CertificateTypeCoverageCheck(result, caqcServicesAtTime, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> hasConsistentTrustService(
			List<TrustedServiceWrapper> caqcServicesAtTime) {
		return new CertificateIssuedByConsistentTrustServiceCheck(result, caqcServicesAtTime, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> isAbleToSelectOneTrustService(List<TrustedServiceWrapper> caqcServicesAtTime) {
		return new IsAbleToSelectOneTrustService(result, caqcServicesAtTime, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> serviceConsistency(TrustedServiceWrapper selectedTrustService) {
		return new ServiceConsistencyCheck(result, selectedTrustService, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> isTrustedCertificateMatchTrustService(TrustedServiceWrapper selectedTrustService) {
		return new TrustedCertificateMatchTrustServiceCheck(result, usedCertificates, selectedTrustService, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> isQualified(QualifiedStatus qualifiedStatus) {
		return new QualifiedCheck(result, qualifiedStatus, validationTime, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> isForEsig(Type type) {
		return new ForEsigCheck(result, type, validationTime, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> isQscd(QSCDStatus qscdStatus) {
		return new QSCDCheck(result, qscdStatus, validationTime, getWarnLevelConstraint());
	}

}
