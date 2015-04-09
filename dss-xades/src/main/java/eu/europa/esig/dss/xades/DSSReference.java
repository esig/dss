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
package eu.europa.esig.dss.xades;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;

/**
 * TODO
 *
 *
 *
 *
 *
 */
public class DSSReference {

	private String id;
	private String uri;
	private String type;

	private DigestAlgorithm digestMethod;

	private DSSDocument contents;

	private List<DSSTransform> transforms;

	/**
	 * The default constructor
	 */
	public DSSReference() {
	}

	public DSSReference(final DSSReference reference) {

		id = reference.id;
		uri = reference.uri;
		type = reference.type;
		digestMethod = reference.digestMethod;
		contents = reference.contents;
		if (reference.transforms != null && reference.transforms.size() > 0) {

			transforms = new ArrayList<DSSTransform>();
			for (final DSSTransform transform : reference.transforms) {

				final DSSTransform dssTransform = new DSSTransform(transform);
				transforms.add(dssTransform);
			}
		}
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getUri() {
		return uri;
	}

	public void setUri(String uri) {
		this.uri = uri;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public DigestAlgorithm getDigestMethodAlgorithm() {
		return digestMethod;
	}

	public void setDigestMethodAlgorithm(DigestAlgorithm digestMethod) {
		this.digestMethod = digestMethod;
	}

	public List<DSSTransform> getTransforms() {
		return transforms;
	}

	public void setTransforms(List<DSSTransform> transforms) {
		this.transforms = transforms;
	}

	public DSSDocument getContents() {
		return contents;
	}

	public void setContents(DSSDocument contents) {
		this.contents = contents;
	}


	@Override
	public String toString() {
		return "DSSReference{" +
			  "id='" + id + '\'' +
			  ", uri='" + uri + '\'' +
			  ", type='" + type + '\'' +
			  ", digestMethod='" + (digestMethod != null ? digestMethod.getName() : digestMethod) + '\'' +
			  ", contents=" + (contents != null ? contents.toString() : contents) +
			  ", transforms=" + transforms +
			  '}';
	}
}
