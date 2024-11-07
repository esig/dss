/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.model.tsl;

import eu.europa.esig.dss.enumerations.MRAEquivalenceContext;

import java.io.Serializable;

/**
 * Contains information about MRA equivalence mapping
 *
 */
public class CertificateContentEquivalence implements Serializable {

	private static final long serialVersionUID = 6732042479139934031L;

	/** Defines the context of the certificate content equivalence (i.e. QcCompliance, QcType, etc.) */
	private MRAEquivalenceContext context;

	/** Defines rules to trigger the equivalence translation */
	private Condition condition;

	/** Contains OIDs of the equivalence rule */
	private QCStatementOids contentReplacement;

	/**
	 * Default constructor instantiating object with null values
	 */
	public CertificateContentEquivalence() {
		// empty
	}

	/**
	 * Get ths certificate content equivalence context
	 *
	 * @return {@link MRAEquivalenceContext}
	 */
	public MRAEquivalenceContext getContext() {
		return context;
	}

	/**
	 * Sets the context of the certificate content equivalence (i.e. QcCompliance, QcType, etc.)
	 *
	 * @param context {@link MRAEquivalenceContext}
	 */
	public void setContext(MRAEquivalenceContext context) {
		this.context = context;
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
