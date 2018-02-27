package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateQualification;
import eu.europa.esig.dss.validation.process.qualification.certificate.CertQualificationMatrix;
import eu.europa.esig.dss.validation.process.qualification.certificate.QSCDStatus;
import eu.europa.esig.dss.validation.process.qualification.certificate.QualifiedStatus;
import eu.europa.esig.dss.validation.process.qualification.certificate.Type;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd.QSCDStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd.QSCDStrategyFactory;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qualified.QualificationStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qualified.QualificationStrategyFactory;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.type.TypeStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.type.TypeStrategyFactory;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class UniqueServiceFilter implements TrustedServiceFilter {

	private static final Logger LOG = LoggerFactory.getLogger(UniqueServiceFilter.class);

	private final CertificateWrapper endEntityCert;

	public UniqueServiceFilter(CertificateWrapper endEntityCert) {
		this.endEntityCert = endEntityCert;
	}

	@Override
	public List<TrustedServiceWrapper> filter(List<TrustedServiceWrapper> trustServices) {
		TrustedServiceWrapper selectedTrustedService = null;

		if (Utils.collectionSize(trustServices) == 1) {
			selectedTrustedService = trustServices.get(0);
		} else if (Utils.isCollectionNotEmpty(trustServices)) {
			LOG.info("More than one selected trust services");

			Set<CertificateQualification> qualificationResults = new HashSet<CertificateQualification>();
			for (TrustedServiceWrapper trustService : trustServices) {
				QualificationStrategy qcStrategy = QualificationStrategyFactory.createQualificationFromCertAndTL(endEntityCert, trustService);
				QualifiedStatus qualifiedStatus = qcStrategy.getQualifiedStatus();

				TypeStrategy typeStrategy = TypeStrategyFactory.createTypeFromCertAndTL(endEntityCert, trustService, qualifiedStatus);
				Type type = typeStrategy.getType();

				QSCDStrategy qscdStrategy = QSCDStrategyFactory.createQSCDFromCertAndTL(endEntityCert, trustService, qualifiedStatus);
				QSCDStatus qscdStatus = qscdStrategy.getQSCDStatus();

				qualificationResults.add(CertQualificationMatrix.getCertQualification(qualifiedStatus, type, qscdStatus));
			}

			if (Utils.collectionSize(qualificationResults) > 1) {
				LOG.warn("Unable to select the trust service ! Several possible conclusions " + qualificationResults);
			} else {
				LOG.info("All trust services conclude with the same result : {}", qualificationResults.iterator().next());
				selectedTrustedService = trustServices.get(0);
			}
		}

		if (selectedTrustedService != null) {
			return Collections.singletonList(selectedTrustedService);
		} else {
			return Collections.emptyList();
		}
	}

}
