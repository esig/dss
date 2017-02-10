package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified;

import eu.europa.esig.dss.validation.process.Condition;

public abstract class AbstractQualificationCondition implements QualificationStrategy, Condition {

	@Override
	public boolean check() {
		return QualifiedStatus.isQC(getQualifiedStatus());
	}

}
