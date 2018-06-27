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
	private final CertificateWrapper rootCertificate;
	private final List<TrustedServiceWrapper> caqcServices;

	private CertificateQualification certificateQualification = CertificateQualification.NA;

	public CertQualificationAtTimeBlock(ValidationTime validationTime, CertificateWrapper signingCertificate, CertificateWrapper rootCertificate,
			List<TrustedServiceWrapper> caqcServices) {
		this(validationTime, null, signingCertificate, rootCertificate, caqcServices);
	}

	public CertQualificationAtTimeBlock(ValidationTime validationTime, Date date, CertificateWrapper signingCertificate, CertificateWrapper rootCertificate,
			List<TrustedServiceWrapper> caqcServices) {
		super(new XmlValidationCertificateQualification());

		this.validationTime = validationTime;
		this.signingCertificate = signingCertificate;
		this.rootCertificate = rootCertificate;
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

		// 1. Filter at date
		TrustedServiceFilter filterByDate = TrustedServicesFilterFactory.createFilterByDate(date);
		List<TrustedServiceWrapper> caqcServicesAtTime = filterByDate.filter(caqcServices);

		ChainItem<XmlValidationCertificateQualification> item = firstItem = item = hasCaQc(caqcServicesAtTime);

		// 2.a Filter by Granted
		TrustedServiceFilter filterByGranted = TrustedServicesFilterFactory.createFilterByGranted();
		caqcServicesAtTime = filterByGranted.filter(caqcServicesAtTime);

		item = item.setNextItem(hasGrantedStatus(caqcServicesAtTime));

		TrustedServiceFilter filterByCertificateType = TrustedServicesFilterFactory
				.createFilterByCertificateType(signingCertificate);
		caqcServicesAtTime = filterByCertificateType.filter(caqcServicesAtTime);

		if (Utils.collectionSize(caqcServicesAtTime) > 1) {

			// 2.b Filter one trust service
			TrustedServiceFilter filterUnique = TrustedServicesFilterFactory.createUniqueServiceFilter(signingCertificate);
			caqcServicesAtTime = filterUnique.filter(caqcServicesAtTime);

			item = item.setNextItem(isAbleToSelectOneTrustService(caqcServicesAtTime));
		}

		TrustedServiceWrapper selectedTrustService = !caqcServicesAtTime.isEmpty() ? caqcServicesAtTime.get(0) : null;

		// 3. Consistency of trust services ?
		item = item.setNextItem(serviceConsistency(selectedTrustService));

		TrustedServiceFilter filterConsistent = TrustedServicesFilterFactory.createConsistentServiceFilter();
		caqcServicesAtTime = filterConsistent.filter(caqcServicesAtTime);
		selectedTrustService = !caqcServicesAtTime.isEmpty() ? caqcServicesAtTime.get(0) : null;

		// 4. Trusted certificate matches the trust service properties ?
		item = item.setNextItem(isTrustedCertificateMatchTrustService(selectedTrustService));

		// 5. QC?
		QualificationStrategy qcStrategy = QualificationStrategyFactory.createQualificationFromCertAndTL(signingCertificate, selectedTrustService);
		QualifiedStatus qualifiedStatus = qcStrategy.getQualifiedStatus();
		item = item.setNextItem(isQualified(qualifiedStatus));

		// 6. Type?
		TypeStrategy typeStrategy = TypeStrategyFactory.createTypeFromCertAndTL(signingCertificate, selectedTrustService, qualifiedStatus);
		Type type = typeStrategy.getType();
		item = item.setNextItem(isForEsig(type));

		// 7. QSCD ?
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

	private ChainItem<XmlValidationCertificateQualification> isAbleToSelectOneTrustService(List<TrustedServiceWrapper> caqcServicesAtTime) {
		return new IsAbleToSelectOneTrustService(result, caqcServicesAtTime, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> serviceConsistency(TrustedServiceWrapper selectedTrustService) {
		return new ServiceConsistencyCheck(result, selectedTrustService, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> isTrustedCertificateMatchTrustService(TrustedServiceWrapper selectedTrustService) {
		return new TrustedCertificateMatchTrustServiceCheck(result, rootCertificate, selectedTrustService, getWarnLevelConstraint());
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
