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

	/** Defines the annotation is signed (covered by a signature/timestamp) */
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
	 * Checks if the signature field is signed
	 * 
	 * @return TRUE if the associated signature field has been signed, FALSE otherwise
	 */
	public boolean isSigned() {
		return signed;
	}

	/**
	 * Sets if the signature field is signed
	 * 
	 * @param signed or not
	 */
	public void setSigned(boolean signed) {
		this.signed = signed;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((annotationBox == null) ? 0 : annotationBox.hashCode());
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		result = prime * result + (signed ? 1231 : 1237);
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
			if (other.name != null) {
				return false;
			}
		} else if (!name.equals(other.name)) {
			return false;
		}
		if (signed != other.signed) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "PdfAnnotation [annotationBox=" + annotationBox + ", name=" + name + ", signed=" + signed + "]";
	}

}
