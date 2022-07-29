package eu.europa.esig.dss.spi.tsl;

import java.util.List;

/**
 * This objects represents a collection of properties extracted from an MRA condition
 *
 */
public class QCStatementOids {

	/** List of QcStatement identifiers to be included */
	private List<String> qcStatementIds;

	/** List of QcType identifiers to be included */
	private List<String> qcTypeIds;

	/** List of QcCClegislation codes to be included */
	private List<String> qcCClegislations;

	/** List of QcStatement identifiers to be removed */
	private List<String> qcStatementIdsToRemove;

	/** List of QcType identifiers to be removed */
	private List<String> qcTypeIdsToRemove;

	/** List of QcCClegislation codes to be removed */
	private List<String> qcCClegislationsToRemove;

	/**
	 * Default constructor instantiating object with null values
	 */
	public QCStatementOids() {
	}

	/**
	 * Gets QcStatement identifiers to be included
	 *
	 * @return a list of {@code String}s
	 */
	public List<String> getQcStatementIds() {
		return qcStatementIds;
	}

	/**
	 * Sets QcStatement identifiers to be included
	 *
	 * @param qcStatementIds a list of {@code String}s
	 */
	public void setQcStatementIds(List<String> qcStatementIds) {
		this.qcStatementIds = qcStatementIds;
	}

	/**
	 * Gets QcType identifiers to be included
	 *
	 * @return a list of {@code String}s
	 */
	public List<String> getQcTypeIds() {
		return qcTypeIds;
	}

	/**
	 * Sets QcType identifiers to be included
	 *
	 * @param qcTypeIds a list of {@code String}s
	 */
	public void setQcTypeIds(List<String> qcTypeIds) {
		this.qcTypeIds = qcTypeIds;
	}

	/**
	 * Gets QcCClegislation codes to be included
	 *
	 * @return a list of {@code String}s
	 */
	public List<String> getQcCClegislations() {
		return qcCClegislations;
	}

	/**
	 * Sets QcCClegislation codes to be included
	 *
	 * @param qcCClegislations a list of {@code String}s
	 */
	public void setQcCClegislations(List<String> qcCClegislations) {
		this.qcCClegislations = qcCClegislations;
	}

	/**
	 * Gets QcStatement identifiers to be removed
	 *
	 * @return a list of {@code String}s
	 */
	public List<String> getQcStatementIdsToRemove() {
		return qcStatementIdsToRemove;
	}

	/**
	 * Sets QcStatement identifiers to be removed
	 *
	 * @param qcStatementIdsToRemove a list of {@code String}s
	 */
	public void setQcStatementIdsToRemove(List<String> qcStatementIdsToRemove) {
		this.qcStatementIdsToRemove = qcStatementIdsToRemove;
	}

	/**
	 * Gets QcType identifiers to be removed
	 *
	 * @return a list of {@code String}s
	 */
	public List<String> getQcTypeIdsToRemove() {
		return qcTypeIdsToRemove;
	}

	/**
	 * Sets QcType identifiers to be removed
	 *
	 * @param qcTypeIdsToRemove a list of {@code String}s
	 */
	public void setQcTypeIdsToRemove(List<String> qcTypeIdsToRemove) {
		this.qcTypeIdsToRemove = qcTypeIdsToRemove;
	}

	/**
	 * Gets QcCClegislation codes to be removed
	 *
	 * @return a list of {@code String}s
	 */
	public List<String> getQcCClegislationsToRemove() {
		return qcCClegislationsToRemove;
	}

	/**
	 * Sets QcCClegislation codes to be removed
	 *
	 * @param qcCClegislationsToRemove a list of {@code String}s
	 */
	public void setQcCClegislationsToRemove(List<String> qcCClegislationsToRemove) {
		this.qcCClegislationsToRemove = qcCClegislationsToRemove;
	}

}
