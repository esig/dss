package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationCertificateQualification;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateQualification;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.CertQualificationMatrix;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.QualificationTime;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.filter.TrustedServiceFilter;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.filter.TrustedServicesFilterFactory;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.QSCDConditionFactory;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.QSCDStatus;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.QSCDStrategy;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.QualificationStrategy;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.QualificationStrategyFactory;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.QualifiedStatus;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type.Type;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type.TypeStrategy;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type.TypeStrategyFactory;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class CertQualificationAtTimeBlock extends Chain<XmlValidationCertificateQualification> {

	private final QualificationTime time;
	private final Date date;
	private final CertificateWrapper signingCertificate;
	private final List<TrustedServiceWrapper> caqcServices;

	private CertificateQualification certificateQualification = CertificateQualification.NA;

	public CertQualificationAtTimeBlock(QualificationTime time, CertificateWrapper signingCertificate, List<TrustedServiceWrapper> caqcServices) {
		this(time, null, signingCertificate, caqcServices);
	}

	public CertQualificationAtTimeBlock(QualificationTime time, Date date, CertificateWrapper signingCertificate, List<TrustedServiceWrapper> caqcServices) {
		super(new XmlValidationCertificateQualification());

		this.time = time;
		this.signingCertificate = signingCertificate;
		this.caqcServices = new ArrayList<TrustedServiceWrapper>(caqcServices);

		switch (time) {
		case CERTIFICATE_ISSUANCE_TIME:
			this.date = signingCertificate.getNotBefore();
			break;
		case VALIDATION_TIME:
		case SIGNING_TIME:
			if (date == null) {
				throw new DSSException("The date must be defined with qualification time : " + time);
			}
			this.date = date;
		default:
			throw new DSSException("Unknown qualification time : " + time);
		}
	}

	@Override
	protected void initChain() {

		// 1. Filter at date
		TrustedServiceFilter filterByDate = TrustedServicesFilterFactory.createFilterByDate(date);
		List<TrustedServiceWrapper> caqcServicesAtTime = filterByDate.filter(caqcServices);

		ChainItem<XmlValidationCertificateQualification> item = firstItem = item = hasCaQcGranted(caqcServicesAtTime);

		if (Utils.isCollectionNotEmpty(caqcServicesAtTime)) {

			// 2. Consistency of trust services ?
			item = item.setNextItem(servicesConsistency(caqcServices));
			item = item.setNextItem(serviceAndCertificateConsistency(caqcServices, signingCertificate));

			// 3. QC?
			QualificationStrategy qcStrategy = QualificationStrategyFactory.createQualificationFromCertAndTL(signingCertificate, caqcServicesAtTime);
			QualifiedStatus qualifiedStatus = qcStrategy.getQualifiedStatus();
			item = item.setNextItem(isQualified(qualifiedStatus));

			// 4. Type?
			TypeStrategy typeStrategy = TypeStrategyFactory.createTypeFromCertAndTL(signingCertificate, caqcServicesAtTime);
			Type type = typeStrategy.getType();
			item = item.setNextItem(isForEsig(type));

			// 5. QSCD ?
			QSCDStrategy qscdStrategy = QSCDConditionFactory.createQSCDFromCertAndTL(signingCertificate, caqcServicesAtTime, qualifiedStatus);
			QSCDStatus qscdStatus = qscdStrategy.getQSCDStatus();
			item = item.setNextItem(isQscd(qscdStatus));

			certificateQualification = CertQualificationMatrix.getCertQualification(qualifiedStatus, type, qscdStatus);
		}

	}

	@Override
	protected void addAdditionalInfo() {
		result.setCertificateQualification(certificateQualification);
		result.setDateTime(date);
	}

	private ChainItem<XmlValidationCertificateQualification> hasCaQcGranted(List<TrustedServiceWrapper> caqcServicesAtTime) {
		return new HasCaQcGrantedCheck(result, caqcServicesAtTime, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> servicesConsistency(List<TrustedServiceWrapper> caqcServices) {
		return new ServiceConsistencyCheck(result, caqcServices, getFailLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> serviceAndCertificateConsistency(List<TrustedServiceWrapper> caqcServices,
			CertificateWrapper signingCertificate) {
		return new CertificateAndServiceConsistencyCheck(result, signingCertificate, caqcServices, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> isQualified(QualifiedStatus qualifiedStatus) {
		return new QualifiedCheck(result, qualifiedStatus, time, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> isForEsig(Type type) {
		return new ForEsigCheck(result, type, time, getWarnLevelConstraint());
	}

	private ChainItem<XmlValidationCertificateQualification> isQscd(QSCDStatus qscdStatus) {
		return new QSCDCheck(result, qscdStatus, time, getWarnLevelConstraint());
	}

}
