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
package eu.europa.esig.dss.enumerations;

/**
 * It identifies the context of the machine processable declarative statement whose reference implementation(s) used by the
 * pointing contracting party is (are) declared in the CertificateContentDeclarationPointingParty element and
 * whose equivalent implementation(s) used by the pointed contracting party is (are) declared in the
 * CertificateContentDeclarationPointedParty element.
 *
 */
public enum MRAEquivalenceContext implements UriBasedEnum {

	/**
	 * Indicate that the CertificateContentReferenceEquivalence element
	 * applies to the context of mapping the respective pointing party and pointed party reference machine processable
	 * statement(s) included in a certificate to declare (as a statement made by the issuing TSP) and to confirm (as a
	 * benchmark for establishing the content of the corresponding TL trust service entry) that it has been
	 * issued as a qualified certificate.
	 */
	QC_COMPLIANCE("http://ec.europa.eu/tools/lotl/mra/QcCompliance"),

	/**
	 *
	 * Indicate that the CertificateContentReferenceEquivalence element applies to the context of mapping the respective
	 * pointing party and pointed party reference machine processable statement(s) included in a certificate to
	 * declare (as a statement made by the issuing TSP) and to confirm (as a benchmark for establishing the content of
	 * the corresponding TL trust service entry) that it has been issued for a certain usage type (i.e. for electronic
	 * signatures, for electronic seals, or for website authentication).
	 */
	QC_TYPE("http://ec.europa.eu/tools/lotl/mra/QcType"),

	/**
	 * Indicate that the CertificateContentReferenceEquivalence element
	 * applies to the context of mapping the respective pointing party and pointed party reference machine processable
	 * statement(s) included in a certificate to declare (as a statement made by the issuing TSP) and to confirm (as a
	 * benchmark for establishing the content of the corresponding TL trust service entry) that the private key,
	 * to which the certified public key corresponds, resides in an EU qualified electronic signature or
	 * seal creation device.
	 */
	QC_QSCD("http://ec.europa.eu/tools/lotl/mra/QcQSCD");

	/** Identifies URI of the MRA equivalence context */
	private final String uri;

	/**
	 * Default constructor
	 *
	 * @param uri {@link String}
	 */
	MRAEquivalenceContext(String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return this.uri;
	}

}
