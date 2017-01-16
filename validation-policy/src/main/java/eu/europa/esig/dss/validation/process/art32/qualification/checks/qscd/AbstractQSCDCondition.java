package eu.europa.esig.dss.validation.process.art32.qualification.checks.qscd;

import eu.europa.esig.dss.validation.process.Condition;

public abstract class AbstractQSCDCondition implements QSCDStrategy, Condition {

	@Override
	public QSCDStatus getQSCDStatus() {
		return check() ? QSCDStatus.QSCD : QSCDStatus.NOT_QSCD;
	}

}
