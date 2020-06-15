package eu.europa.esig.dss.spi.tsl;

import java.util.List;

public class QCStatementOids {

	private List<String> qcStatementIds;
	private List<String> qcTypeIds;

	public List<String> getQcStatementIds() {
		return qcStatementIds;
	}

	public void setQcStatementIds(List<String> qcStatementIds) {
		this.qcStatementIds = qcStatementIds;
	}

	public List<String> getQcTypeIds() {
		return qcTypeIds;
	}

	public void setQcTypeIds(List<String> qcTypeIds) {
		this.qcTypeIds = qcTypeIds;
	}

}
