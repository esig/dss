package eu.europa.esig.dss.spi.tsl;

/**
 * Contains information about MRA equivalence mapping
 *
 */
public class CertificateContentEquivalence {

	/** Defines rules to trigger the equivalence translation */
	private Condition condition;

	/** Contains OIDs of the equivalence rule */
	private QCStatementOids contentReplacement;

	/**
	 * Default constructor instantiating object with null values
	 */
	public CertificateContentEquivalence() {
	}

	/**
	 * Gets the equivalence condition
	 *
	 * @return {@link Condition}
	 */
	public Condition getCondition() {
		return condition;
	}

	/**
	 * Sets the equivalence condition
	 *
	 * @param condition {@link Condition}
	 */
	public void setCondition(Condition condition) {
		this.condition = condition;
	}

	/**
	 * Gets the defined OIDs
	 *
	 * @return {@link QCStatementOids}
	 */
	public QCStatementOids getContentReplacement() {
		return contentReplacement;
	}

	/**
	 * Sets the equivalence OIDs
	 *
	 * @param contentReplacement {@link QCStatementOids}
	 */
	public void setContentReplacement(QCStatementOids contentReplacement) {
		this.contentReplacement = contentReplacement;
	}

}
