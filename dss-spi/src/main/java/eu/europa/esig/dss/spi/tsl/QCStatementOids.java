/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
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
