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
package eu.europa.esig.dss.pdf;

import java.util.Objects;

/**
 * Contains relative information about a PDF annotation
 *
 */
public class PdfAnnotation {

	/** Defines the box of the annotation */
	private final AnnotationBox annotationBox;

	/** The name of the annotation */
	private String name;

	/** Defines whether annotation is signed */
	private boolean signed;

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

	/**
	 * Gets whether the annotation field is signed
	 *
	 * @return TRUE if the annotation field contains a signature, FALSE otherwise
	 */
	public boolean isSigned() {
		return signed;
	}

	/**
	 * Sets whether the annotation field is signed
	 *
	 * @param signed  whether the annotation field is signed
	 */
	public void setSigned(boolean signed) {
		this.signed = signed;
	}

	@Override
	public int hashCode() {
		int result = annotationBox != null ? annotationBox.hashCode() : 0;
		result = 31 * result + (name != null ? name.hashCode() : 0);
		result = 31 * result + (signed ? 1 : 0);
		return result;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof PdfAnnotation)) return false;

		PdfAnnotation that = (PdfAnnotation) o;

		if (signed != that.signed) return false;
		if (!Objects.equals(annotationBox, that.annotationBox))
			return false;
        return Objects.equals(name, that.name);
    }

	@Override
	public String toString() {
		return "PdfAnnotation [annotationBox=" + annotationBox + ", name=" + name + ", signed=" + signed + "]";
	}

}
