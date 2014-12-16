/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.parameter;

/**
 * TODO
 * <p/>
 * <p> DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class DSSTransform {

	private String algorithm;

	String elementName;
	String namespace;
	String textContent;
	private boolean perform = false;

	public DSSTransform() {
	}

	/**
	 * This is a copy constructor.
	 *
	 * @param transform
	 */
	public DSSTransform(final DSSTransform transform) {

		algorithm = transform.algorithm;
		perform = transform.perform;
		elementName = transform.elementName;
		namespace = transform.namespace;
		textContent = transform.textContent;
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	/**
	 * The framework (4.3.0-RC) is able to cope in automated manner only with some transformations: canonicalization & {@code Transforms.TRANSFORM_XPATH}. You need to set this
	 * property to tell to the framework to perform the transformation. It applies only for {@code SignaturePackaging.ENVELOPED}.
	 * The default value is {@code false}.
	 *
	 * @param perform indicates if the transformation should be performed
	 */
	public void setPerform(boolean perform) {
		this.perform = perform;
	}

	public boolean isPerform() {
		return perform;
	}

	public String getElementName() {
		return elementName;
	}

	public void setElementName(String elementName) {
		this.elementName = elementName;
	}

	public String getNamespace() {
		return namespace;
	}

	public void setNamespace(String namespace) {
		this.namespace = namespace;
	}

	public String getTextContent() {
		return textContent;
	}

	public void setTextContent(String textContent) {
		this.textContent = textContent;
	}

	@Override
	public String toString() {
		return "DSSTransform{" +
			  "algorithm='" + algorithm + '\'' +
			  ", elementName='" + elementName + '\'' +
			  ", namespace='" + namespace + '\'' +
			  ", textContent='" + textContent + '\'' +
			  ", perform=" + perform +
			  '}';
	}
}
