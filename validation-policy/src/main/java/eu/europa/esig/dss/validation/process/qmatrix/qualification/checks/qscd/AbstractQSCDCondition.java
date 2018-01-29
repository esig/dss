package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd;

import eu.europa.esig.dss.validation.process.Condition;

public abstract class AbstractQSCDCondition implements QSCDStrategy, Condition {

	@Override
	public boolean check() {
		return QSCDStatus.isQSCD(getQSCDStatus());
	}

}
