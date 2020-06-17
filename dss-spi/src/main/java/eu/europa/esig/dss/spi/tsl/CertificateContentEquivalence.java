package eu.europa.esig.dss.spi.tsl;

public class CertificateContentEquivalence {

	private Condition condition;

	private QCStatementOids contentReplacement;

	public Condition getCondition() {
		return condition;
	}

	public void setCondition(Condition condition) {
		this.condition = condition;
	}

	public QCStatementOids getContentReplacement() {
		return contentReplacement;
	}

	public void setContentReplacement(QCStatementOids contentReplacement) {
		this.contentReplacement = contentReplacement;
	}

}
