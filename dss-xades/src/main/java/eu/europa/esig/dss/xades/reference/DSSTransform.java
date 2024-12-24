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
package eu.europa.esig.dss.xades.reference;

import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.Serializable;

/**
 * Defines a transform used for a reference transformations
 */
public interface DSSTransform extends Serializable {
	
	/**
	 * Returns a particular transformation algorithm name
	 * 
	 * @return {@link String} algorithm name of transformation
	 */
	String getAlgorithm();
	
	/**
	 * Specifies a namespace for the transformation elements
	 * 
	 * @param namespace {@link DSSNamespace} uri
	 */
	void setNamespace(DSSNamespace namespace);

	/**
	 * Executes a transform on the provided {@code DSSTransformOutput}
	 *
	 * @param transformOutput {@link DSSTransformOutput}
	 * @return {@link DSSTransformOutput} after applying the transform
	 */
	DSSTransformOutput performTransform(DSSTransformOutput transformOutput);
	
	/**
	 * Creates a Transform element DOM and appends it to the {@code parentNode}
	 * 
	 * @param document   {@link Document} to add transform for
	 * @param parentNode {@link Element} to append transform to
	 * @return created transform {@link Element}
	 */
	Element createTransform(Document document, Element parentNode);

}
