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
package eu.europa.esig.dss.pdf;

/**
 * Contains relative information about a PDF annotation
 *
 */
public class PdfAnnotation {

	/** Defines the box of the annotation */
	private final AnnotationBox annotationBox;

	/** The name of the annotation */
	private String name;

	/**
	 * Default constructor
	 * 
	 * @param annotationBox {@link AnnotationBox}
	 */
	public PdfAnnotation(final AnnotationBox annotationBox) {
		this.annotationBox = annotationBox;
	}
	
	/**
	 * Returns the {@code AnnotationBox}
	 * 
	 * @return {@link AnnotationBox}
	 */
	public AnnotationBox getAnnotationBox() {
		return annotationBox;
	}
	
	/**
	 * Returns a name of the annotation
	 * 
	 * @return {@link String} name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Sets a name of the annotation
	 * 
	 * @param name {@link String} annotation name
	 */
	public void setName(String name) {
		this.name = name;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((annotationBox == null) ? 0 : annotationBox.hashCode());
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		PdfAnnotation other = (PdfAnnotation) obj;
		if (annotationBox == null) {
			if (other.annotationBox != null) {
				return false;
			}
		} else if (!annotationBox.equals(other.annotationBox)) {
			return false;
		}
		if (name == null) {
			return other.name == null;
		} else return name.equals(other.name);
	}

	@Override
	public String toString() {
		return "PdfAnnotation [annotationBox=" + annotationBox + ", name=" + name + "]";
	}

}
